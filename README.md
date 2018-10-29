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
* Currently supported grant types
  * `client_credentials`
* Implemented as a Slim middleware (https://www.slimframework.com/)

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
GPL-3.0+