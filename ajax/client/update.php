<?php

/**
 * Create a oauth client entry
 *
 * @return string
 * @throws \QUI\Exception
 */
QUI::$Ajax->registerFunction(
    'package_quiqqer_oauth-server_ajax_client_update',
    function ($clientId, $data) {
        QUI\OAuth\Clients\Handler::updateOAuthClient(
            $clientId,
            json_decode($data, true)
        );
    },
    array('clientId', 'data')
);
