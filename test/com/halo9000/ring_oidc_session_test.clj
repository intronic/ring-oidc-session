(ns com.halo9000.ring-oidc-session-test
  (:require [clojure.test :refer [deftest is testing]]
            [clojure.string :as str]
            [ring.util.http-response :as http]
            [ring.util.http-status :as status]
            [ring.mock.request :as mock]
            [slingshot.slingshot :refer [throw+]]
            [ring.util.codec :as codec]
            [clj-http.client]
            [com.halo9000.ring-oidc-session :as oidc :refer [wrap-oidc-session]]))

;; suppress log messages
(alter-var-root #'oidc/*LOG-401* (constantly false))
(alter-var-root #'oidc/*LOG-OTHER* (constantly false))

(def profiles-config
  ; minimal example
  {:minimal-profile {:userinfo-uri    "https://example.com/oidc/v1/userinfo"
                     :end-session-uri "https://example.com/oidc/v1/end_session"
                     :revocation-uri  "https://example.com/oauth2/revoke"
                     :logout-oidc-uri "/app/end-session"
                     :logout-ring-uri "/app/logout"
                     :landing-uri     "/home"
                     :client-id        "CLIENTID"}

  ; modified from ring-oauth2 example (:github profile in https://github.com/weavejester/ring-oauth2#usage)
  ;   github.com for instance does not implement OIDC end_session endpoint
  ;     https://token.actions.githubusercontent.com/.well-known/openid-configuration
   :extended-profile {:authorize-uri    "https://example.com/eg-ring-oauth2/authorize"
                      :access-token-uri "https://example.com/eg-ring-oauth2/access-token"
                      :redirect-uri     "/eg-ring-oauth2/test/callback"
                      :launch-uri       "/eg-ring-oauth2/test"
                      :landing-uri      "/"
                      :scopes           [:user :project]
                      :client-id        "EXTENDEDID"
                      :client-secret    "01234567890abcdef"
                      :userinfo-uri    "https://example.com/eg-ring-oauth2/oidc/v1/userinfo"
                      :revocation-uri  "https://example.com/eg-ring-oauth2/revoke"
                      :end-session-uri "https://example.com/eg-ring-oauth2/oidc/v1/end_session"
                      :logout-oidc-uri "/eg-ring-oauth2/end-session"
                      :logout-ring-uri "/eg-ring-oauth2/logout"}})

(defn add-id [profiles id]
  (assoc (get profiles id) :id id))

(defn get-redirect-response-path-and-params [response]
  (let [location (get-in response [:headers "Location"])
        [path query] (str/split location #"\?" 2)]
    [path (codec/form-decode query)]))

(defn logged-out-redirect [url] (assoc (http/found url) :session nil))

(deftest test-resolve-uri
  (testing "resolves"
    (is (= "http://localhost/xyz"
           (#'oidc/resolve-uri "xyz" (mock/request :get "/abc"))))))

(deftest test-api-get
  (testing "passes parameters"
    (with-redefs [clj-http.client/get (fn [url req] [url req])]
      (is (= ["uri" {:accept :json
                     :as :json
                     :oauth-token "TOKEN"}]
             (#'oidc/api-get "uri" "TOKEN"))))))

(deftest test-api-post
  (testing "passes parameters"
    (with-redefs [clj-http.client/post (fn [url req] [url req])]
      (is (= ["uri"
              {:form-params {:id 1 :token "REFRESH"}
               :oauth-token "TOKEN"}]
             (#'oidc/api-post "uri" {:id 1 :token "REFRESH"} "TOKEN"))))))

(deftest test-post-oidc-revoke
  (testing "success"
    (with-redefs [oidc/api-post (fn [uri params access-token] (http/ok {:uri uri :form-params params :token access-token}))]
      (is (= {:uri "/abc" :form-params {:client_id "123" :token "REFRESH"} :token "TOK"}
             (oidc/post-oidc-revoke "/abc" "TOK" "123" "REFRESH")))))
  ;; TODO: add failure modes
  )

(deftest test-make-ring-logout-handler
  (let [test-prof (add-id profiles-config :minimal-profile)
        acc-tok "TOK"
        ref-tok "REFRESH"
        sess {:ring.middleware.oauth2/access-tokens
              {:minimal-profile
               {:token acc-tok :refresh-token ref-tok :id-token "IDTOK"}}}
        req (-> (mock/request :get "/assume-correct-path") (assoc  :session sess))]

    (testing "handler"
      ; handler ignores request uri and simply redirects (assumes route is set correctly by caller)
      (let [post (atom nil)]
        (with-redefs [com.halo9000.ring-oidc-session/post-oidc-revoke
                      (fn [uri access-token client-id refresh-token]
                        (reset! post [uri access-token client-id refresh-token]))]
          (is (= (logged-out-redirect (:landing-uri test-prof))
                 ((#'oidc/make-ring-logout-handler test-prof) req)))
          (is (= [(:revocation-uri test-prof)
                  acc-tok
                  (:client-id test-prof)
                  ref-tok]
                 @post)))))

    (testing "handler async"
      (let [post (atom nil)]
        (with-redefs [com.halo9000.ring-oidc-session/post-oidc-revoke
                      (fn [uri access-token client-id refresh-token]
                        (reset! post [uri access-token client-id refresh-token]))]
          (let [res (atom nil)
                resp ((#'oidc/make-ring-logout-handler test-prof)
                      req
                      (fn respond [response] (reset! res response))
                      (fn raise [error] (reset! res error)))]
            (is (= (logged-out-redirect (:landing-uri test-prof))
                   @res))
            (is (= resp @res))
            (is (= [(:revocation-uri test-prof)
                    acc-tok
                    (:client-id test-prof)
                    ref-tok]
                   @post))))))))

(deftest test-make-oidc-logout-handler
  (let [res (atom nil)
        test-prof (add-id profiles-config :minimal-profile)
        req (assoc-in (mock/request :get "/assume-correct-path") [:session :ring.middleware.oauth2/access-tokens :minimal-profile :id-token] "mocktoken")]

    (testing "handler"
        ; handler ignores request uri and simply redirects (assumes route is set correctly by caller)
        ; :id is added to profile from enclosing map by caller
        ; :id-token must be in request :session map
      (let [resp ((#'oidc/make-oidc-logout-handler test-prof) req)
            [path params] (get-redirect-response-path-and-params resp)]
        (is (= {:status status/found :session nil} (select-keys resp [:status :session])))
        (is (= (:end-session-uri test-prof) path))
        (is (= {"id_token_hint" "mocktoken"
                "post_logout_redirect_uri" (str "http://localhost" (:landing-uri test-prof))}
               params))))

    (testing "handler async"
      (let [resp ((#'oidc/make-oidc-logout-handler test-prof)
                  req
                  (fn respond [response] (reset! res response))
                  (fn raise [error] (reset! res error)))
            [path params] (get-redirect-response-path-and-params @res)]
        (is (= {:status status/found :session nil} (select-keys @res [:status :session])))
        (is (= (:end-session-uri test-prof) path))
        (is (= {"id_token_hint" "mocktoken"
                "post_logout_redirect_uri" (str "http://localhost" (:landing-uri test-prof))}
               params))
        (is (= resp @res))

        ; error branch - mock 'ring.util.codec/form-encode' function to throw in order to simulate error scenario
        (with-redefs [ring.util.codec/form-encode (fn [_] (throw (ex-info "err" {})))]
          (let [res (atom nil)
                req (assoc (mock/request :get "/anything") :session "mocksession")
                resp ((#'oidc/make-oidc-logout-handler test-prof)
                      req
                      (fn respond [response] (reset! res response))
                      (fn raise [error] (reset! res error)))]
            (is (instance? clojure.lang.ExceptionInfo @res))
            (is (= nil resp))))))))

(deftest test-fetch-oidc-userinfo
  (testing "success modes"
    (with-redefs [oidc/api-get (fn [uri access-token] (http/ok {:uri uri :token access-token}))]
      (is (= {:uri "/abc" :token "TOK"} (oidc/fetch-oidc-userinfo "/abc" "TOK"))))
    (with-redefs [oidc/api-get (fn [uri access-token] (throw+ (http/unauthorized {:uri uri :token access-token})))]
      (is (nil? (oidc/fetch-oidc-userinfo "/abc" "TOK"))))
    (with-redefs [oidc/api-get (fn [uri access-token] (throw+ (http/im-a-teapot {:uri uri :token access-token})))]
      (is (nil? (oidc/fetch-oidc-userinfo "/abc" "TOK")))))

  (testing "failure modes"
    (with-redefs [oidc/api-get (fn [uri access-token] (throw+ (ex-info "failed" {:uri uri :token access-token})))]
      (is (nil? (oidc/fetch-oidc-userinfo "/abc" "TOK"))))))


(defn simulate-oauth2-token- [profile-key token id-token] {profile-key {:token token :id-token id-token}})

(deftest test-get-ring-oauth2-entry
  (let [test-map (simulate-oauth2-token- :profile-key "tok" "id-tok")]
    (testing "success"
      (is (nil? (oidc/get-ring-oauth2-entry (mock/request :get "/some-path"))))
      (is (nil? (oidc/get-ring-oauth2-entry (assoc-in (mock/request :get "/some-path")
                                                      [:session :ring.middleware.oauth2/access-tokens]
                                                      nil))))
      (is (= [:profile-key (:profile-key test-map)]
             (oidc/get-ring-oauth2-entry (assoc-in (mock/request :get "/some-path")
                                                   [:session :ring.middleware.oauth2/access-tokens]
                                                   test-map)))))

    (testing "failure on anything else that is not a single-entry map"
      (let [test-fail-map (merge (simulate-oauth2-token- :profile-key "tok" "id-tok")
                                 (simulate-oauth2-token- :second-key "tok" "id-tok"))]

        (is (thrown? clojure.lang.ExceptionInfo
                     (oidc/get-ring-oauth2-entry (assoc-in (mock/request :get "/some-path")
                                                           [:session :ring.middleware.oauth2/access-tokens]
                                                           test-fail-map))))
        (is (thrown? clojure.lang.ExceptionInfo
                     (oidc/get-ring-oauth2-entry (assoc-in (mock/request :get "/some-path")
                                                           [:session :ring.middleware.oauth2/access-tokens]
                                                           [:a :list]))))
        (is (thrown? clojure.lang.ExceptionInfo
                     (oidc/get-ring-oauth2-entry (assoc-in (mock/request :get "/some-path")
                                                           [:session :ring.middleware.oauth2/access-tokens]
                                                           "some string"))))))))

(deftest test-wrap-userinfo
  (let [user-info {:user "bob"}]
    (testing "userinfo is added to :landing-uri requests"
      (with-redefs [oidc/fetch-oidc-userinfo (fn [_ _] user-info)]
        (let [handler (oidc/wrap-userinfo identity profiles-config)]
          (doseq [[id uri] (map (juxt first #(get-in profiles-config %))
                                [[:minimal-profile :landing-uri]
                                 [:extended-profile :landing-uri]])]
            (let [request (assoc-in (mock/request :get uri)
                                    [:session :ring.middleware.oauth2/access-tokens]
                                    (simulate-oauth2-token- id "tok" "id-tok"))]
              (is (= (assoc request :com.halo9000.ring-oidc-session/userinfo user-info)
                     (handler request))))))))

    (testing "request is unchanged for other config URIs"
      (with-redefs [oidc/fetch-oidc-userinfo (fn [_ _] user-info)]
        (let [handler (oidc/wrap-userinfo identity profiles-config)]
          (doseq [[id uri] (map (juxt first #(get-in profiles-config %))
                                [[:minimal-profile :logout-oidc-uri]
                                 [:minimal-profile :logout-ring-uri]
                                 [:extended-profile :logout-oidc-uri]
                                 [:extended-profile :logout-ring-uri]
                                 [:extended-profile :redirect-uri]
                                 [:extended-profile :launch-uri]])]
            (let [request (assoc-in (mock/request :get uri)
                                    [:session :ring.middleware.oauth2/access-tokens]
                                    (simulate-oauth2-token- id "tok" "id-tok"))]
              (is (= request (handler request))))))))

    (testing "request is unchanged for other URIs"
      (with-redefs [oidc/fetch-oidc-userinfo (fn [_ _] user-info)]
        (let [handler (oidc/wrap-userinfo identity profiles-config)]
          (doseq [[uri session] [["/somewhere" nil]
                                 ["/anywhere" {:ring.middleware.oauth2/access-tokens
                                               (simulate-oauth2-token- :key "TOK" "IDTOK")}]]]
            (let [request (assoc-in (mock/request :get uri)
                                    [:session]
                                    session)]
              (is (= request (handler request))))))))

    (testing "async middleware succeeds"
      (with-redefs [oidc/fetch-oidc-userinfo (fn [_ _] user-info)]
        (let [res (atom nil)
              err (atom nil)
              success-fn (fn [resp] (reset! res resp))
              error-fn (fn [e] (reset! err e))
              handler (oidc/wrap-userinfo identity profiles-config)]
          (doseq [[id uri] (map (juxt first #(get-in profiles-config %))
                                [[:minimal-profile :landing-uri]
                                 [:extended-profile :landing-uri]])]
            (let [request (assoc-in (mock/request :get uri)
                                    [:session :ring.middleware.oauth2/access-tokens]
                                    (simulate-oauth2-token- id "tok" "id-tok"))]
              (is (= (assoc request :com.halo9000.ring-oidc-session/userinfo user-info)
                     (handler request success-fn error-fn)))
              (is (= (assoc request :com.halo9000.ring-oidc-session/userinfo user-info)
                     @res))
              (is (= nil @err)))))))

    (testing "async middleware fails"
      (with-redefs [oidc/fetch-oidc-userinfo (fn [_ _] (throw (ex-info "fail" user-info)))]
        (let [res (atom nil)
              err (atom nil)
              success-fn (fn [resp] (reset! res resp))
              error-fn (fn [e] (reset! err e))
              handler (oidc/wrap-userinfo identity profiles-config)]
          (doseq [[id uri] (map (juxt first #(get-in profiles-config %))
                                [[:minimal-profile :landing-uri]
                                 [:extended-profile :landing-uri]])]
            (let [request (assoc-in (mock/request :get uri)
                                    [:session :ring.middleware.oauth2/access-tokens]
                                    (simulate-oauth2-token- id "tok" "id-tok"))]
              (is (nil? (handler request success-fn error-fn)))
              (is (instance? clojure.lang.ExceptionInfo @err))
              (is (= nil @res)))))))))

(defn make-dummy-401-responder [state]
  (fn [_]
    (reset! state (http/unauthorized))))

(defn url-upto-query
  "Return the url up to the ? query portion, if any."
  [url]
  (if-let [i (str/index-of url "?")]
    (subs url 0 i)
    url))

(deftest test-url-to-query
  (is (= "http://example.com/def" (url-upto-query "http://example.com/def?ghi")))
  (is (= "http://example.com/def" (url-upto-query "http://example.com/def"))))

(deftest test-wrap-oidc-session
  ;; For each profile name (prof-key), query each request uri (req-key),
  ;; and check the response matches the expected (exp-resp-key)
  (with-redefs [clj-http.client/get (fn [url & _] (throw (ex-info "handler should not call GET" url)))
                clj-http.client/post (fn [url & _]
                                       ;; return dummy OK response on revocation, otherwise error
                                       (if (str/includes? url "/revoke")
                                         {:status 200 :body nil}
                                         (throw (ex-info "handler should only POST on revocation-uri" url))))]

    (doseq [[prof-key req->resp] {:minimal-profile [[:logout-oidc-uri :end-session-uri]
                                                    [:logout-ring-uri :landing-uri]]
                                  :extended-profile [[:logout-oidc-uri :end-session-uri]
                                                     [:logout-ring-uri :landing-uri]]}
            [req-key exp-resp-key] req->resp]
      (testing (str "handler " prof-key ": " req-key " -> " exp-resp-key)
        (let [fallthrough-res (atom nil)
              handler (wrap-oidc-session (make-dummy-401-responder fallthrough-res) profiles-config)
              url (get-in profiles-config [prof-key req-key])
              expected-url (get-in profiles-config [prof-key exp-resp-key])
            ;; call the handler with a mock request
              resp (handler (mock/request :get url))]
          (is (= {:status status/found :session nil} (select-keys resp [:status :session])))
          (is (= expected-url (url-upto-query (get-in resp [:headers "Location"]))))
          (is (= nil @fallthrough-res)))))

    (testing "fallback path handler"
      (doseq [unhandled-uri (conj
                           ; these should not have handlers
                             (map #(get-in profiles-config %) [[:minimal-profile :landing-uri]
                                                               [:extended-profile :landing-uri]])
                           ; nor anything else
                             "/some-other-uri")]
        (let [fallthrough-res (atom nil)
              handler (wrap-oidc-session (make-dummy-401-responder fallthrough-res) profiles-config)
              resp (handler (mock/request :get unhandled-uri))]
          (is (= (http/unauthorized) resp))
          (is (= @fallthrough-res resp)))))))
