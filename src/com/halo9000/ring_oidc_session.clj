(ns com.halo9000.ring-oidc-session
  (:require [ring.util.request :as req]
            [ring.util.http-response :as http]
            [ring.util.http-status :as status]
            [ring.util.codec :as codec]
            [clj-http.client :as client]
            [missionary.core :as m]
            [clojure.tools.logging.readable :as log]))

(def ^:dynamic *LOG-401* false) ; unauthorized is expected on oidc calls with expired tokens
(def ^:dynamic *LOG-OTHER* true)

(defn- resolve-uri
  "Resolve path to full uri of request including scheme & host."
  [path request]
  (-> (req/request-url request)
      (java.net.URI/create)
      (.resolve path)
      str))

;; TODO: change api-fetch/post to be one call for both, and try 1 time to repeat the call with refresh token on 401
(defn- api-fetch [uri access-token]
  (m/? (m/via m/blk (client/get uri {:accept :json
                                     :as :json
                                     :oauth-token access-token}))))

(defn- api-post [uri body access-token]
  (m/? (m/via m/blk (client/post uri {:body body
                                      :accept :json
                                      :as :json
                                      :oauth-token access-token}))))

(defn post-oidc-revoke
  "Revoke the refresh (and access) tokens."
  [uri access-token client-id refresh-token]
  (let [body {:token refresh-token :client-id client-id}
        resp (api-post uri body access-token)]
    (condp = (:status resp)
      status/ok (:body resp)
      status/unauthorized (do (when *LOG-401* (log/warn 'post-oidc-revoke--401 :uri uri :resp resp))
                              nil) ; no discrimination for expired vs invalid token - TODO: the same as for fetch-oidc-userinfo above
      (do
        (when *LOG-401* (log/warn 'post-oidc-revoke--failed :client-id client-id :resp resp))
        nil))))

(defn- make-ring-logout-handler
  "Revoke OIDC refresh token, remove ring session, and redirect to landing-uri."
  [{:keys [revocation-uri landing-uri id client-id] :as prof}]
  ;; :ring.middleware.oauth2/access-tokens keys (from zitadel): {:id {:token :extra-data :expires :refresh-token :id-token}}
  (fn handler
    ([request]
     (let [token (get-in request [:session :ring.middleware.oauth2/access-tokens id :token])
           refresh (get-in request [:session :ring.middleware.oauth2/access-tokens id :refresh-token])]
       (post-oidc-revoke revocation-uri token client-id refresh))
     (-> (http/found landing-uri) (assoc :session nil)))
    ([request respond _] (respond (handler request))))) ; TODO: handle errors

(defn- make-oidc-logout-handler
  "Remove ring session and redirect to OIDC end_session endpoint."
  [{:keys [end-session-uri landing-uri id]}]
  (fn handler
    ([request]
     (-> end-session-uri
         (str "?" (codec/form-encode
                   {:id_token_hint (get-in request [:session :ring.middleware.oauth2/access-tokens id :id-token])
                    :post_logout_redirect_uri (resolve-uri landing-uri request)}))
         (http/found)
         (assoc :session nil)))
    ([request respond raise]
     (when-let [response (try (handler request)
                              (catch Exception e (raise e) false))]
       (respond response)))))

(defn fetch-oidc-userinfo
  "Return userinfo from OIDC endpoint or nil if unauthorized or other error."
  [uri access-token]
  (let [resp (api-fetch uri access-token)]
    (condp = (:status resp)
      status/ok (:body resp)
      ;; no discrimination for expired vs invalid token
      status/unauthorized (do (when *LOG-401* (log/warn 'fetch-oidc-userinfo--401 :uri uri :resp resp))
                              nil)
      ;; log some other issue that could be handled
      (do (when *LOG-OTHER* (log/warn 'fetch-oidc-userinfo--failed :uri uri :resp resp))
          nil))))

(defn get-ring-oauth2-entry
  "Return [id token-map] for ring-oauth2 session in request or nil if :ring.middleware.oauth2/access-tokens not present."
  ; :ring.middleware.oauth2/access-tokens keys (from zitadel): {:id {:token :extra-data :expires :refresh-token :id-token}}
  ; oauth2/access-tokens has a single key and value
  [request]
  (when-let [entry (get-in request [:session :ring.middleware.oauth2/access-tokens])]
    (if (and (map? entry) (= 1 (count entry)))
      (first entry)
      (throw (ex-info "Unexpected oauth2 access-tokens entry" {:entry entry})))))

(defn wrap-userinfo
  "If request has a valid token, add ::userinfo key with results from OIDC userinfo_endpoint before calling next handler."
  [handler profile-map]
  (let [landing-uri (into #{} (map :landing-uri (vals profile-map)))]
    (fn userinfo-handler
      ([request]
       (if (landing-uri (:uri request))
         (let [[id token-map] (get-ring-oauth2-entry request)
               userinfo (when-let [token (:token token-map)]
                          (let [userinfo-uri (get-in profile-map [id :userinfo-uri])]
                            (fetch-oidc-userinfo userinfo-uri token)))]
           (handler (assoc request ::userinfo userinfo)))
         (handler request)))
      ([request respond raise]
       (when-let [response (try (userinfo-handler request)
                                (catch Exception e (raise e) false))]
         (respond response))))))

(defn wrap-oidc-session [handler profile-map]
  (let [profiles (for [[k v] profile-map] (assoc v :id k))
        logout-ring (into {} (map (juxt :logout-ring-uri make-ring-logout-handler)) profiles)
        logout-oidc (into {} (map (juxt :logout-oidc-uri make-oidc-logout-handler)) profiles)
        handler (wrap-userinfo handler profile-map)]
    (fn [{:keys [uri] :as request}]
      (if-let [ring-logout-handler (logout-ring uri)]
        (ring-logout-handler request)
        (if-let [oidc-logout-handler (logout-oidc uri)]
          (oidc-logout-handler request)
          (handler request))))))
