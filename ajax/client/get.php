<?php

/**
 * Return the client data
 *
 * @return string
 * @throws \QUI\Exception
 */
QUI::$Ajax->registerFunction(
    'package_quiqqer_oauth-server_ajax_client_get',
    function ($clientId) {
        return QUI\OAuth\Clients\Handler::getOAuthClient($clientId);
    },
    array('clientId')
);
