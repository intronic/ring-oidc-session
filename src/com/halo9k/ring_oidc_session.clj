(ns com.halo9k.ring-oidc-session
  (:require [ring.util.request :as req]
            [ring.util.http-response :as http]
            [ring.util.codec :as codec]))

(defn- resolve-uri
  "Resolve path to full uri of request including scheme & host."
  [path request]
  (-> (req/request-url request)
      (java.net.URI/create)
      (.resolve path)
      str))

(defn- make-ring-logout-handler
  "Remove ring session and redirect."
  [{:keys [post-logout-uri landing-uri] :as _profile}]
  (fn handler
    ([_request]
     (-> (http/found (or post-logout-uri landing-uri "/")) (assoc :session nil)))
    ([request respond _] (respond (handler request))))) ; no need for try/raise here as redirect is a simple map

(defn- make-oidc-logout-handler
  "Remove ring session and redirect to OIDC end_session endpoint."
  [{:keys [end-session-uri post-logout-oidc-uri post-logout-uri landing-uri id] :as _profile}]
  (fn handler
    ([request]
     (-> end-session-uri
         (str "?" (ring.util.codec/form-encode
                   {:id_token_hint (get-in request [:session :ring.middleware.oauth2/access-tokens id :id-token])
                    :post_logout_redirect_uri (resolve-uri (or post-logout-oidc-uri post-logout-uri landing-uri "/") request)}))
         (http/found)
         (assoc :session nil)))
    ([request respond raise]
     (when-let [response (try (handler request)
                              (catch Exception e (raise e) false))]
       (respond response)))))

(defn wrap-oidc-session [handler profiles]
  (let [profiles (for [[k v] profiles] (assoc v :id k))
        logout-ring (into {} (map (juxt :logout-ring-uri identity)) profiles)
        logout-oidc (into {} (map (juxt :logout-oidc-uri identity)) profiles)]
    (fn [{:keys [uri] :as request}]
      (if-let [profile (logout-ring uri)]
        ((make-ring-logout-handler profile) request)
        (if-let [profile (logout-oidc uri)]
          ((make-oidc-logout-handler profile) request)
          (handler request))))))
