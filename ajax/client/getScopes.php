<?php

/**
 * Return all scopes (REST entry points) for clients
 *
 * @return array
 * @throws \QUI\Exception
 */

use QUI\REST\Server;

QUI::$Ajax->registerFunction(
    'package_quiqqer_oauth-server_ajax_client_getScopes',
    function () {
        $scopes = Server::getInstance()->getEntryPoints();

        foreach ($scopes as $k => $scope) {
            switch ($scope) {
                case '/oauth/token':
                case '/oauth/authorize':
                    unset($scopes[$k]);
                    break;
            }
        }

        return array_values($scopes);
    },
    [],
    'Permission::checkAdminUser'
);
