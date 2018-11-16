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
         * @param {Number} clientId
         * @param {Object} Data
         *
         * @return {Promise}
         */
        updateClient: function (clientId, Data) {
            return new Promise(function (resolve, reject) {
                QUIAjax.post('package_quiqqer_oauth-server_ajax_client_update', resolve, {
                    'package': pkg,
                    clientId : clientId,
                    data     : JSON.encode(Data),
                    onError  : reject
                });
            });
        },

        /**
         * Delete an OAuth2 client
         *
         * @param {Number} clientId
         *
         * @return {Promise}
         */
        deleteClient: function (clientId) {
            return new Promise(function (resolve, reject) {
                QUIAjax.post('package_quiqqer_oauth-server_ajax_client_remove', resolve, {
                    'package': pkg,
                    clientId : clientId,
                    onError  : reject
                });
            });
        },

        /**
         * Return the client data
         *
         * @param {String} clientId - ID of the OAuth client
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
         * Get all OAuth clients linked to a QUIQQER user
         *
         * @param {Number} userId - QUIQQER user id
         * @returns {Promise}
         */
        getClientList: function (userId) {
            return new Promise(function (resolve, reject) {
                QUIAjax.get('package_quiqqer_oauth-server_ajax_client_list', resolve, {
                    'package': 'quiqqer/oauth-server',
                    userId   : userId,
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
        },

        /**
         * Return scope protection settings
         *
         * @return {Promise}
         */
        getProtectedScopes: function () {
            return new Promise(function (resolve, reject) {
                QUIAjax.get('package_quiqqer_oauth-server_ajax_client_getProtectedScopes', resolve, {
                    'package': pkg,
                    onError  : reject
                });
            });
        },

        /**
         * Return all scope usage limits for an OAuth client
         *
         * @param {String} clientId - ID of the OAuth client
         * @return {Promise}
         */
        getLimits: function (clientId) {
            return new Promise(function (resolve, reject) {
                QUIAjax.get('package_quiqqer_oauth-server_ajax_client_getLimits', resolve, {
                    'package': pkg,
                    clientId : clientId,
                    onError  : reject
                });
            });
        },

        /**
         * Reset usage limits for an OAuth client for a specific scope
         *
         * @param {String} clientId - ID of the OAuth client
         * @param {String} scope
         * @return {Promise}
         */
        resetLimits: function (clientId, scope) {
            return new Promise(function (resolve, reject) {
                QUIAjax.post('package_quiqqer_oauth-server_ajax_client_resetLimits', resolve, {
                    'package': pkg,
                    clientId : clientId,
                    scope    : scope,
                    onError  : reject
                });
            });
        }
    });
});
