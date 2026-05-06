<?php

use QUI\OAuth\Permission;

QUI::$Ajax->registerFunction(
    'package_quiqqer_oauth-server_ajax_client_get',
    /**
     * Return the client data
     *
     * @return array
     * @throws \QUI\Exception
     */
    function ($clientId) {
        $clientData = QUI\OAuth\Clients\Handler::getOAuthClient($clientId);
        $clientData['scope_restrictions'] = json_decode($clientData['scope_restrictions'], true);

        return $clientData;
    },
    ['clientId'],
    [
        'Permission::checkAdminUser',
        Permission::MANAGE_CLIENTS->value
    ]
);
