<?php

/**
 * Return all scopes (REST entry points) for clients
 *
 * @return array
 * @throws \QUI\Exception
 */
QUI::$Ajax->registerFunction(
    'package_quiqqer_oauth-server_ajax_client_getScopes',
    function () {
        return \QUI\REST\Server::getInstance()->getEntryPoints();
    },
    [],
    'Permission::checkAdminUser'
);
