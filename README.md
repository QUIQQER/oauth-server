![QUIQQER OAuth Server](bin/images/Readme.jpg)

QUIQQER OAuth Server
========

Control all your QUIQQER REST API requests via OAuth authentication and set individual query limits for each OAuth client. 

Package Name:

    quiqqer/oauth-server


Features
--------
* Create and manage OAuth clients with individual access configuration
* All REST API endpoints that are registered by the REST providers in your QUIQQER system are treated
as OAuth scopes
  * Each scope can be individually configured for each OAuth client
  * Limit queries per time interval (i.e. "1000 queries / hour") or allow unlimited access
  * Optionally turn off OAuth authentication for REST API endpoints in the settings
* Supported grant types
  * `authorization_code` with mandatory PKCE S256 and explicit user consent
  * `refresh_token` with refresh token rotation
  * `client_credentials`
* OAuth Authorization Server and Protected Resource metadata
* Resource-bound access and refresh tokens
* Authenticated token revocation
* Implemented as a Slim middleware (https://www.slimframework.com/)

Authorization clients
---------------------
Authorization clients are registered statically by an administrator. The package intentionally does not expose an
unauthenticated Dynamic Client Registration endpoint. Register ChatGPT and agent clients through
`QUI\OAuth\Clients\Handler::createAuthorizationClient()`, supplying the exact redirect URIs, allowed REST resource
identifiers, allowed scopes and whether the client is public.

The Authorization Server issuer and default protected resource identifier are the absolute QUIQQER REST base URL.
Discovery is exposed at the origin root, independently of the configured REST base path:

* `/.well-known/oauth-authorization-server`
* `/.well-known/oauth-protected-resource`

The metadata returned there points to the OAuth endpoints below the REST base path, for example
`/api/oauth/authorize`, `/api/oauth/token` and `/api/oauth/revoke`.

If an OAuth authorization request is opened without an authenticated QUIQQER session, the authorization endpoint
shows a login link. Configure the project's login URL through `general.authorization_login_url`. The URL receives the
original authorization request in the `quiqqer_oauth_return` query parameter; the login integration must return the
user to that URL after successful authentication.

Installation
------------
The Package Name is: quiqqer/oauth-server

Contribute
----------
- Project: https://dev.quiqqer.com/quiqqer/oauth-server
- Issue Tracker: https://dev.quiqqer.com/quiqqer/oauth-server/issues
- Source Code: https://dev.quiqqer.com/quiqqer/oauth-server/tree/master

Support
-------
If you found any errors or have wishes or suggestions for improvement,
please contact us by email at support@pcsg.de.

We will transfer your message to the responsible developers.

License
-------
LGPL-3.0-or-later
