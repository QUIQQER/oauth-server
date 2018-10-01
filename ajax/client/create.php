<?php

use QUI\Utils\Security\Orthos;
use QUI\OAuth\Clients\Handler as OAuthClientsHandler;

/**
 * Create a new OAuth2 client
 *
 * @return string
 * @throws \QUI\Exception
 */
QUI::$Ajax->registerFunction(
    'package_quiqqer_oauth-server_ajax_client_create',
    function ($userId, $scopeSettings, $title = null) {
        if (!empty($title)) {
            $title = Orthos::clear($title);
        }

        OAuthClientsHandler::createOAuthClient(
            QUI::getUsers()->get((int)$userId),
            Orthos::clearArray(json_decode($scopeSettings, true)),
            $title
        );
    },
    ['userId', 'scopeSettings', 'title'],
    'Permission::checkAdminUser'
);
