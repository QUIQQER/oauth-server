/**
 * OAuthServer handler
 *
 * @module package/quiqqer/oauth-server/bin/backend/OAuthServer
 * @author www.pcsg.de (Patrick Müller)
 */
define('package/quiqqer/oauth-server/bin/backend/OAuthServer', [

    'package/quiqqer/oauth-server/bin/backend/classes/OAuthServer'

], function (OAuthServer) {
    "use strict";
    return new OAuthServer();
});
