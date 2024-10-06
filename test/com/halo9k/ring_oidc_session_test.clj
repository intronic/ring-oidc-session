(ns com.halo9k.ring-oidc-session-test
  (:require [clojure.test :refer [deftest is testing]]
            [clojure.string :as str]
            [ring.util.http-response :as http]
            [ring.util.http-status :as status]
            [ring.mock.request :as mock]
            [ring.util.codec :as codec]
            [clj-http.client]
            [com.halo9k.ring-oidc-session :as oidc :refer [wrap-oidc-session]]))


(def profiles-config
  ; minimal example
  {:minimal-profile {:userinfo-uri    "https://example.com/oidc/v1/userinfo"
                     :end-session-uri "https://example.com/oidc/v1/end_session"
                     :logout-oidc-uri "/app/end-session"
                     :logout-ring-uri "/app/logout"
                     :landing-uri     "/home"}

  ; modified from ring-oauth2 example (:github profile in https://github.com/weavejester/ring-oauth2#usage)
  ;   github.com for instance does not implement OIDC end_session endpoint
  ;     https://token.actions.githubusercontent.com/.well-known/openid-configuration
   :extended-profile {:authorize-uri    "https://example.com/eg-ring-oauth2/authorize"
                      :access-token-uri "https://example.com/eg-ring-oauth2/access-token"
                      :redirect-uri     "/eg-ring-oauth2/test/callback"
                      :launch-uri       "/eg-ring-oauth2/test"
                      :landing-uri      "/"
                      :scopes           [:user :project]
                      :client-id        "abcdef"
                      :client-secret    "01234567890abcdef"
                      :userinfo-uri    "https://example.com/eg-ring-oauth2/oidc/v1/userinfo"
                      :end-session-uri "https://example.com/eg-ring-oauth2/oidc/v1/end_session"
                      :logout-oidc-uri "/eg-ring-oauth2/end-session"
                      :logout-ring-uri "/eg-ring-oauth2/logout"}})

(defn- logged-out-redirect [url] (assoc (http/found url) :session nil))

(deftest test-private-helpers
  (testing "test-resolve-uri"
    (is (= "http://localhost/xyz"
           (#'oidc/resolve-uri "xyz" (mock/request :get "/abc")))))

  (testing "test-api-fetch"
    (with-redefs [clj-http.client/get (fn [uri token] [uri token])]
      (is (= ["uri" {:accept :json
                     :oauth-token "TOKEN"}]
             (#'oidc/api-fetch "uri" "TOKEN")))))

  (testing "make-ring-logout-handler"
      ; handler ignores request uri and simply redirects (assumes route is set correctly by caller)
    (let [req (assoc (mock/request :get "/assume-correct-path") :session "mocksession")]
      (is (= (logged-out-redirect (:landing-uri (profiles-config :minimal-profile)))
             ((#'oidc/make-ring-logout-handler (profiles-config :minimal-profile)) req)))))

  (testing "make-ring-logout-handler ring async"
    (let [res (atom nil)
          req (assoc (mock/request :get "/assume-correct-path") :session "mocksession")
          _resp ((#'oidc/make-ring-logout-handler (profiles-config :minimal-profile))
                 req
                 (fn respond [response] (reset! res response))
                 (fn raise [error] (reset! res error)))]
      (is (= (logged-out-redirect (:landing-uri (profiles-config :minimal-profile)))
             @res))
      (is (= _resp @res))))

  (testing "make-oidc-logout-handler"
      ; handler ignores request uri and simply redirects (assumes route is set correctly by caller)
      ; :id is added to profile from enclosing map by caller
      ; :id-token must be in request :session map
    (let [test-prof (assoc (profiles-config :minimal-profile) :id :minimal-profile)
          req (assoc-in (mock/request :get "/assume-correct-path") [:session :ring.middleware.oauth2/access-tokens :minimal-profile :id-token] "mocktoken")
          resp ((#'oidc/make-oidc-logout-handler test-prof) req)
          location (get-in resp [:headers "Location"])
          [path query] (str/split location #"\?" 2)
          params (codec/form-decode query)]
      (is (= {:status status/found :session nil} (select-keys resp [:status :session])))
      (is (= (:end-session-uri (profiles-config :minimal-profile)) path))
      (is (= {"id_token_hint" "mocktoken"
              "post_logout_redirect_uri" (str "http://localhost" (:landing-uri (profiles-config :minimal-profile)))}
             params))))

  (testing "make-oidc-logout-handler ring async"
    (let [res (atom nil)
          test-prof (assoc (profiles-config :minimal-profile) :id "some-id")
          req (assoc-in (mock/request :get "/assume-correct-path") [:session :ring.middleware.oauth2/access-tokens "some-id" :id-token] "mocktoken")
          _resp ((#'oidc/make-oidc-logout-handler test-prof)
                 req
                 (fn respond [response] (reset! res response))
                 (fn raise [error] (reset! res error)))
          location (get-in @res [:headers "Location"])
          [path query] (str/split location #"\?" 2)
          params (codec/form-decode query)]
      (is (= {:status status/found :session nil} (select-keys @res [:status :session])))
      (is (= _resp @res))
      (is (= (:end-session-uri (profiles-config :minimal-profile))
             path))
      (is (= {"id_token_hint" "mocktoken"
              "post_logout_redirect_uri" (str "http://localhost" (:landing-uri (profiles-config :minimal-profile)))}
             params))

      ; error branch - mock 'ring.util.codec/form-encode' function to throw in order to simulate error scenario
      (with-redefs [ring.util.codec/form-encode (fn [_] (throw (ex-info "err" {})))]
        (let [res (atom nil)
              req (assoc (mock/request :get "/anything") :session "mocksession")
              resp ((#'oidc/make-oidc-logout-handler (profiles-config :minimal-profile))
                    req
                    (fn respond [response] (reset! res response))
                    (fn raise [error] (reset! res error)))]
          (is (instance? clojure.lang.ExceptionInfo @res))
          (is (= nil resp)))))))

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

(deftest test-fetch-oidc-userinfo
  (testing "success modes"
    (with-redefs [oidc/api-fetch (fn [uri access-token] (http/ok {:uri uri :token access-token}))]
      (is (= {:uri "/abc" :token "TOK"} (oidc/fetch-oidc-userinfo "/abc" "TOK"))))
    (with-redefs [oidc/api-fetch (fn [uri access-token] (http/unauthorized {:uri uri :token access-token}))]
      (is (nil? (oidc/fetch-oidc-userinfo "/abc" "TOK"))))
    (with-redefs [oidc/api-fetch (fn [uri access-token] (http/im-a-teapot {:uri uri :token access-token}))]
      (is (nil? (oidc/fetch-oidc-userinfo "/abc" "TOK")))))

  (testing "failure modes"
    (with-redefs [oidc/api-fetch (fn [uri access-token] (throw (ex-info "failed" {:uri uri :token access-token})))]
      (is (thrown? clojure.lang.ExceptionInfo
                   (oidc/fetch-oidc-userinfo "/abc" "TOK"))))))

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
              (is (= (assoc request :com.halo9k.ring-oidc-session/userinfo user-info)
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
              (is (= (assoc request :com.halo9k.ring-oidc-session/userinfo user-info)
                     (handler request success-fn error-fn)))
              (is (= (assoc request :com.halo9k.ring-oidc-session/userinfo user-info)
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
  ; profile name with expected [request response] uri keys
  (doseq [[prof-key req->resp] {:minimal-profile [[:logout-oidc-uri :end-session-uri]
                                                  [:logout-ring-uri :landing-uri]]
                                :extended-profile [[:logout-oidc-uri :end-session-uri]
                                                   [:logout-ring-uri :landing-uri]]}
          [req-key resp-key] req->resp]
    (testing (str "handler " prof-key ": " req-key " -> " resp-key)
      (let [fallthrough-res (atom nil)
            handler (wrap-oidc-session (make-dummy-401-responder fallthrough-res) profiles-config)
            url (get-in profiles-config [prof-key req-key])
            expected-url (get-in profiles-config [prof-key resp-key])
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
        (is (= @fallthrough-res resp))))))
