<?php

/**
 * Create a oauth client entry
 *
 * @return string
 * @throws \QUI\Exception
 */
QUI::$Ajax->registerFunction(
    'package_quiqqer_oauth-server_ajax_client_create',
    function () {
        QUI\OAuth\Clients\Handler::createOAuthClient(
            QUI::getUserBySession()
        );
    }
);
