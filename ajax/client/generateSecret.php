<?php

use QUI\OAuth\Clients\Handler as OAuthClientsHandler;

QUI::$Ajax->registerFunction(
    'package_quiqqer_oauth-server_ajax_client_generateSecret',
    /**
     * Generate a client secret.
     * @return string
     * @throws QUI\Exception
     */
    function () {
        try {
            return OAuthClientsHandler::generatePassword();
        } catch (\Exception $Exception) {
            QUI\System\Log::writeException($Exception);

            throw new QUI\Exception([
                    'quiqqer/oauth-server',
                    'message.ajax.general_error'
                ]
            );
        }
    },
    [],
    'Permission::checkAdminUser'
);
