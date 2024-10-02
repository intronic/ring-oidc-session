(ns com.halo9k.ring-oidc-session-test
  (:require [clojure.test :refer [deftest is testing]]
            [clojure.string :as str]
            [ring.util.http-response :as http]
            [ring.mock.request :as mock]
            [ring.util.codec :as codec]
            [com.halo9k.ring-oidc-session :as oidc :refer [wrap-oidc-session]]))


(def profiles-config
  ; minimal example
  {:minimal-profile {:userinfo-uri    "https://example.com/oidc/v1/userinfo"
                     :end-session-uri    "https://example.com/oidc/v1/end_session"
                     :logout-oidc-uri      "/app/end-session"
                     :post-logout-oidc-uri "/app/end-session/callback"
                     :logout-ring-uri      "/app/logout"
                     :post-logout-uri      "/home"}

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
      (is (= (#'oidc/resolve-uri "xyz" (mock/request :get "/abc"))
             "http://localhost/xyz")))

    (testing "make-ring-logout-handler"
      (let [req (assoc (mock/request :get "/anything") :session "mocksession")
            resp ((#'oidc/make-ring-logout-handler (profiles-config :minimal-profile)) req)]
        (is (= (logged-out-redirect (:post-logout-uri (profiles-config :minimal-profile)))
               resp)))

    ; fallback for :post-logout-uri
      (let [resp ((#'oidc/make-ring-logout-handler (dissoc (profiles-config :minimal-profile) :post-logout-uri))
                  (mock/request :get "/anything"))]
        (is (= (logged-out-redirect "/")
               resp))))

    (testing "make-ring-logout-handler ring async"
      (let [res (atom nil)
            req (assoc (mock/request :get "/anything") :session "mocksession")
            _resp ((#'oidc/make-ring-logout-handler (profiles-config :minimal-profile))
                   req
                   (fn respond [response] (reset! res response))
                   (fn raise [error] (reset! res error)))]
        (is (= (logged-out-redirect (:post-logout-uri (profiles-config :minimal-profile)))
               @res))
        (is (= _resp @res))))

    (testing "make-oidc-logout-handler"
    ; :id must be added to profile from enclosing map
    ; :id-token must be in request :session map
      (let [test-prof (assoc (profiles-config :minimal-profile) :id "some-id")
            req (assoc-in (mock/request :get "/anything") [:session :ring.middleware.oauth2/access-tokens "some-id" :id-token] "mocktoken")
            resp ((#'oidc/make-oidc-logout-handler test-prof) req)
            location (get-in resp [:headers "Location"])
            [path query] (str/split location #"\?" 2)
            params (codec/form-decode query)]
        (is (= {:status 302 :session nil} (select-keys resp [:status :session])))
        (is (= (:end-session-uri (profiles-config :minimal-profile)) path))
        (is (= {"id_token_hint" "mocktoken"
                "post_logout_redirect_uri" (str "http://localhost" (:post-logout-oidc-uri (profiles-config :minimal-profile)))}
               params))

      ; fallback for :post-logout-oidc-uri
        (let [test-prof (dissoc test-prof :post-logout-oidc-uri)
              resp ((#'oidc/make-oidc-logout-handler test-prof) req)
              location (get-in resp [:headers "Location"])
              [_path query] (str/split location #"\?" 2)
              params (codec/form-decode query)]
          (is (= params {"id_token_hint" "mocktoken"
                         "post_logout_redirect_uri" (str "http://localhost" (:post-logout-uri (profiles-config :minimal-profile)))}))

        ; fallback for :post-logout-uri
          (let [test-prof (dissoc test-prof :post-logout-uri)
                resp ((#'oidc/make-oidc-logout-handler test-prof) req)
                location (get-in resp [:headers "Location"])
                [_path query] (str/split location #"\?" 2)
                params (codec/form-decode query)]
            (is (= params {"id_token_hint" "mocktoken"
                           "post_logout_redirect_uri" (str "http://localhost" "/")}))))))

    (testing "make-oidc-logout-handler ring async"
      (let [res (atom nil)
            test-prof (assoc (profiles-config :minimal-profile) :id "some-id")
            req (assoc-in (mock/request :get "/anything") [:session :ring.middleware.oauth2/access-tokens "some-id" :id-token] "mocktoken")
            _resp ((#'oidc/make-oidc-logout-handler test-prof)
                   req
                   (fn respond [response] (reset! res response))
                   (fn raise [error] (reset! res error)))
            location (get-in @res [:headers "Location"])
            [path query] (str/split location #"\?" 2)
            params (codec/form-decode query)]
        (is (= {:status 302 :session nil} (select-keys @res [:status :session])))
        (is (= _resp @res))
        (is (= (:end-session-uri (profiles-config :minimal-profile))
               path))
        (is (= {"id_token_hint" "mocktoken"
                "post_logout_redirect_uri" (str "http://localhost" (:post-logout-oidc-uri (profiles-config :minimal-profile)))}
               params))

      ; error branch - mock 'ring.util.codec/form-encode' function to throw to simulate error
        (with-redefs [ring.util.codec/form-encode (fn [_] (throw (ex-info "err" {})))]
          (let [res (atom nil)
                req (assoc (mock/request :get "/anything") :session "mocksession")
                resp ((#'oidc/make-oidc-logout-handler (profiles-config :minimal-profile))
                      req
                      (fn respond [response] (reset! res response))
                      (fn raise [error] (reset! res error)))]
            (is (instance? clojure.lang.ExceptionInfo @res))
            (is (= nil resp)))))))

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
                                                  [:logout-ring-uri :post-logout-uri]]
                                :extended-profile [[:logout-oidc-uri :end-session-uri]
                                                   [:logout-ring-uri :landing-uri]]}
          [req-key resp-key] req->resp]
    (testing (str "handler " prof-key ": " req-key " -> " resp-key)
      (let [fallthrough-res (atom nil)
            handler (wrap-oidc-session (make-dummy-401-responder fallthrough-res) profiles-config)
            url (get-in profiles-config [prof-key req-key])
            expected-url (get-in profiles-config [prof-key resp-key])
            resp (handler (mock/request :get url))]
        (is (= {:status 302 :session nil} (select-keys resp [:status :session])))
        (is (= expected-url (url-upto-query (get-in resp [:headers "Location"]))))
        (is (= nil @fallthrough-res)))))

  (testing "fallback path handler"
    (doseq [unhandled-uri (conj
                           ; these should not have handlers
                           (map #(get-in profiles-config %) [[:minimal-profile :post-logout-uri]
                                                             [:extended-profile :landing-uri]])
                           ; nor anything else
                           "/some-other-uri")]
      (let [fallthrough-res (atom nil)
            handler (wrap-oidc-session (make-dummy-401-responder fallthrough-res) profiles-config)
            resp (handler (mock/request :get unhandled-uri))]
        (is (= (http/unauthorized) resp))
        (is (= @fallthrough-res resp))))))
