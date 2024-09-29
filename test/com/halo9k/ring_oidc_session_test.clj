(ns com.halo9k.ring-oidc-session-test
  (:require [clojure.test :refer [deftest is testing]]
            [clojure.string :as str]
            [ring.mock.request :as mock]
            [ring.util.codec :as codec]
            [com.halo9k.ring-oidc-session :as oidc :refer [wrap-oidc-session]]))

(def test-profile
  {:end-session-uri    "https://example.com/oidc/v1/end_session"
   :logout-ring-uri      "/app/logout"
   :logout-oidc-uri      "/app/end-session"
   :post-logout-oidc-uri "/app/end-session/callback"
   :post-logout-uri      "/home"})

(def test-profile-oauth2
  {:authorize-uri    "https://example.com/oauth2/authorize"
   :access-token-uri "https://example.com/oauth2/access-token"
   :redirect-uri     "/oauth2/test/callback"
   :launch-uri       "/oauth2/test"
   :landing-uri      "/"
   :scopes           [:user :project]
   :client-id        "abcdef"
   :client-secret    "01234567890abcdef"})

(deftest private-helpers
  (testing "test-resolve-uri"
    (is (= (#'oidc/resolve-uri "xyz" (mock/request :get "/abc"))
           "http://localhost/xyz")))

  (testing "make-ring-logout-handler"
    (let [req (assoc (mock/request :get "/anything") :session "mocksession")
          resp ((#'oidc/make-ring-logout-handler test-profile) req)]
      (is (= (:status resp) 302))
      (is (= (:headers resp) {"Location" (:post-logout-uri test-profile)}))
      (is (= (:session resp) nil)))

    ; fallback for :post-logout-uri
    (let [resp ((#'oidc/make-ring-logout-handler (dissoc test-profile :post-logout-uri))
                (mock/request :get "/anything"))]
      (is (= (:status resp) 302))
      (is (= (:headers resp) {"Location" "/"}))))

  (testing "make-oidc-logout-handler"
    ; :id must be added to profile from enclosing map
    ; :id-token must be in request :session map
    (let [test-prof (assoc test-profile :id "some-id")
          req (assoc-in (mock/request :get "/anything") [:session :ring.middleware.oauth2/access-tokens "some-id" :id-token] "mocktoken")
          resp ((#'oidc/make-oidc-logout-handler test-prof) req)
          location (get-in resp [:headers "Location"])
          [path query] (str/split location #"\?" 2)
          params (codec/form-decode query)]
      (is (= (:status resp) 302))
      (is (= path (:end-session-uri test-profile)))
      (is (= params {"id_token_hint" "mocktoken"
                     "post_logout_redirect_uri" (str "http://localhost" (:post-logout-oidc-uri test-profile))}))

      ; fallback for :post-logout-oidc-uri
      (let [test-prof (dissoc test-prof :post-logout-oidc-uri)
            resp ((#'oidc/make-oidc-logout-handler test-prof) req)
            location (get-in resp [:headers "Location"])
            [path query] (str/split location #"\?" 2)
            params (codec/form-decode query)]
        (is (= params {"id_token_hint" "mocktoken"
                       "post_logout_redirect_uri" (str "http://localhost" (:post-logout-uri test-profile))}))

        ; fallback for :post-logout-uri
        (let [test-prof (dissoc test-prof :post-logout-uri)
              resp ((#'oidc/make-oidc-logout-handler test-prof) req)
              location (get-in resp [:headers "Location"])
              [path query] (str/split location #"\?" 2)
              params (codec/form-decode query)]
          (is (= params {"id_token_hint" "mocktoken"
                         "post_logout_redirect_uri" (str "http://localhost" "/")})))))))

