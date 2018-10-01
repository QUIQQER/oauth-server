<?php

use QUI\Utils\Security\Orthos;

/**
 * Edit an Oauth2 client
 *
 * @param int $clientId
 * @param array $data
 * @return void
 * @throws \QUI\Exception
 */
QUI::$Ajax->registerFunction(
    'package_quiqqer_oauth-server_ajax_client_update',
    function ($clientId, $data) {
        QUI\OAuth\Clients\Handler::updateOAuthClient(
            $clientId,
            Orthos::clearArray(json_decode($data, true))
        );
    },
    ['clientId', 'data'],
    'Permission::checkAdminUser'
);
