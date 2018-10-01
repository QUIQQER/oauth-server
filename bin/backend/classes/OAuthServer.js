/**
 * OAuthServer handler
 *
 * @module package/quiqqer/oauth-server/bin/backend/classes/OAuthServer
 * @author www.pcsg.de (Patrick Müller)
 */
define('package/quiqqer/oauth-server/bin/backend/classes/OAuthServer', [

    'Ajax'

], function (QUIAjax) {
    "use strict";

    var pkg = 'quiqqer/oauth-server';

    return new Class({

        Type: 'package/quiqqer/oauth-server/bin/backend/classes/OAuthServer',

        /**
         * Create a new OAuth2 client
         *
         * @param {Number} userId
         * @param {Object} ScopeSettings
         * @param {String} title
         *
         * @return {Promise}
         */
        createClient: function (userId, ScopeSettings, title) {
            return new Promise(function (resolve, reject) {
                QUIAjax.post('package_quiqqer_oauth-server_ajax_client_create', resolve, {
                    'package'    : pkg,
                    userId       : userId,
                    scopeSettings: JSON.encode(ScopeSettings),
                    title        : title,
                    onError      : reject
                });
            });
        },

        /**
         * Update an OAuth2 client
         *
         * @param {Number} userId
         * @param {Object} Data
         *
         * @return {Promise}
         */
        updateClient: function (userId, Data) {
            return new Promise(function (resolve, reject) {
                QUIAjax.post('package_quiqqer_oauth-server_ajax_client_update', resolve, {
                    'package': pkg,
                    userId   : userId,
                    data     : JSON.encode(Data),
                    onError  : reject
                });
            });
        },

        /**
         * Return the client data
         *
         * @param {String} clientId - ID of the client
         * @returns {Promise}
         */
        getClient: function (clientId) {
            return new Promise(function (resolve, reject) {
                QUIAjax.get('package_quiqqer_oauth-server_ajax_client_get', resolve, {
                    'package': 'quiqqer/oauth-server',
                    clientId : clientId,
                    onError  : reject
                });
            });
        },

        /**
         * Return all scopes (REST entry points) for clients
         *
         * @return {Promise}
         */
        getScopes: function () {
            return new Promise(function (resolve, reject) {
                QUIAjax.get('package_quiqqer_oauth-server_ajax_client_getScopes', resolve, {
                    'package': pkg,
                    onError  : reject
                });
            });
        }
    });
});
