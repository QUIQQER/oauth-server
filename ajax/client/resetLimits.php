<?php

/**
 * this file contains package_quiqqer_oauth-server_ajax_client_resetLimits
 */

use QUI\OAuth\Clients\Handler as ClientsHandler;

/**
 * Reset usage limits for an OAuth client for a specific scope
 *
 * @param int $clientId
 * @param string $scope
 * @return array
 * @throws \QUI\Exception
 */
QUI::$Ajax->registerFunction(
    'package_quiqqer_oauth-server_ajax_client_resetLimits',
    function ($clientId, $scope) {
        try {
            ClientsHandler::resetClientLimits($clientId, $scope);
        } catch (QUI\OAuth\Exception $Exception) {
            QUI::getMessagesHandler()->addError(
                QUI::getLocale()->get(
                    'quiqqer/oauth-server',
                    'message.ajax.client.resetLimits.error',
                    [
                        'error' => $Exception->getMessage()
                    ]
                )
            );

            return;
        } catch (Exception $Exception) {
            QUI\System\Log::writeException($Exception);

            QUI::getMessagesHandler()->addError(
                QUI::getLocale()->get(
                    'quiqqer/oauth-server',
                    'message.ajax.general_error'
                )
            );

            return;
        }

        QUI::getMessagesHandler()->addSuccess(
            QUI::getLocale()->get(
                'quiqqer/oauth-server',
                'message.ajax.client.resetLimits.success',
                [
                    'clientId' => $clientId,
                    'scope' => $scope
                ]
            )
        );
    },
    ['clientId', 'scope'],
    'Permission::checkAdminUser'
);
