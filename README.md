# com.halo9000/ring-oidc-session  [![Build Status](https://github.com/intronic/ring-oidc-session/actions/workflows/test.yml/badge.svg)](https://github.com/intronic/ring-oidc-session/actions/workflows/test.yml)  [![Clojars Project](https://img.shields.io/clojars/v/com.halo9000/ring-oidc-session.svg)](https://clojars.org/com.halo9000/ring-oidc-session)

[Ring][] middleware that adds OIDC session handling (`userinfo` and `end_session` endpoints).
Based on and to be used together with  [ring-oauth2][].

The middleware function to use is `ring-oidc-session/wrap-oidc-session`.

* The following config entries are added to the `ring-oauth2` profile map:

```clojure
(require '[ring-oidc-session :refer [wrap-oidc-session]])

  (-> handler
    (wrap-oidc-session
      {:your-oidc-provider
        { ;; minimal options for this middleware:
          :userinfo-uri     "{oidc_idp_domain}/oidc/v1/userinfo"
          :revocation-uri   "{oidc_idp_domain}/oauth/v2/revoke"
          :end-session-uri  "{oidc_idp_domain}/oidc/v1/end_session"
          :logout-oidc-uri  "/your/end-oidc-session/route"
          :logout-ring-uri  "/your/logout/route"
          :client-id        "abcde" ; from ring-oauth2 options .. required for revocation endpoint
          ;; ... other ring-oauth2 options...
        })
  )
```

* `wrap-oidc-session` uses the config to add one request-modifying middleware and 3 ring routes

* A request-modifying middleware will be applied to the `:landing-uri` route:
  * If `:ring.middleware.oauth2/access-tokens` are found in the `:session` key of the request then the OIDC userinfo endpoint (`:userinfo-uri`) will be queried.
    * The profile id (eg: `:your-oidc-provider`, above) will be used to find the profile with the `:userinfo-uri`.
  * On successful validation, the userinfo results will be added to the request under the key: `::userinfo`.
  * On validation failure, the `::userinfo` request key will be associated with a `nil` value.

* A `:logout-oidc-uri` route will be added which will clear the ring session and redirect the user to the OIDC end_session endpoint (`:end-session-uri`).
  * The OIDC IdP should redirect the user to a preconfigured app URI.
  * This is the *Single Sign Out* counterpart to *Single Sign On* (SSO).
  * This should clear any user sessions with the OIDC IdP, as well as the users ring session.

* A `:logout-ring-uri` route will be added which will clear the ring session and post to the OIDC revocation endpoint to revoke the refresh (and access) tokens.
  * This is the *Log Out of this Device* option.
  * This should end this session on this device, but not any other SSO sessions they may have.

[ring]: https://github.com/ring-clojure/ring
[oauth 2.0]: https://oauth.net/2/
[ring-oauth2]: https://github.com/weavejester/ring-oauth2

### Middleware Order

This should be placed above the `wrap-oauth2` handler, where `oidc-profile-map` in the merged profile map of oauth2 and oidc-session data above:

```clojure
   ...middleware...
   (wrap-oidc-session oidc-profile-map)
   (wrap-oauth2 oidc-profile-map)
   ...middleware...
```
#### State mismatch error

* If ring-oauth2 returns a `State mismatch` error, you likely need to add `SameSite:Lax` cookie option
  to allow for cross-site GET cookie for auth state.
  * See notes at [ring-oauth2][].
* Plus, in production you shauld review the site defaults (eg use secure-site-defaults and possibly :proxy true).
  * See notes at [ring-defaults][].

```clojure
    (wrap-defaults (-> ringdef/site-defaults (assoc-in [:session :cookie-attrs :same-site] :lax)))
    (wrap-params)
```
[ring-defaults]: https://github.com/ring-clojure/ring-defaults

## Notes

Invoke a library API function from the command-line:

    $ clojure -X com.halo9000.ring-oidc-session/foo :a 1 :b '"two"'
    {:a 1, :b "two"} "Hello, World!"

Run the project's tests (they'll fail until you edit them):

    $ clojure -T:build test

Run a specific test:

    $ clj -M:test -v com.halo9000.ring-oidc-session-test/make-ring-logout-handler

Run the project's CI pipeline and build a JAR (this will fail until you edit the tests to pass):

    $ clojure -T:build ci

This will produce an updated `pom.xml` file with synchronized dependencies inside the `META-INF`
directory inside `target/classes` and the JAR in `target`. You can update the version (and SCM tag)
information in generated `pom.xml` by updating `build.clj`.

Apply (and push) the version tag to the git repo:

    $ clojure -T:build git-tag-version

Deploy it to Clojars -- needs `CLOJARS_USERNAME` and `CLOJARS_PASSWORD` environment
variables (requires the `ci` & `git-tag-version` tasks be run first):

    $ clojure -T:build deploy

Your library will be deployed to com.halo9000/ring-oidc-session on clojars.org by default.

Install it locally (requires the `ci` task be run first):

    $ clojure -T:build install

### Test coverage

* See [test-coverage][]

* Run tests and produce fully annotatated source coverage report in `target/coverage/`:

```bash
clj -M:test:coverage
firefox target/coverage/index.html
```

[test-coverage]: https://github.com/cloverage/cloverage
