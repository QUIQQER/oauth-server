<?php

/**
 * this file contains package_quiqqer_oauth-server_ajax_client_update
 */

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
        try {
            QUI\OAuth\Clients\Handler::updateOAuthClient(
                $clientId,
                Orthos::clearArray(json_decode($data, true))
            );
        } catch (QUI\OAuth\Exception $Exception) {
            QUI::getMessagesHandler()->addError(
                QUI::getLocale()->get(
                    'quiqqer/oauth-server',
                    'message.ajax.client.update.error',
                    [
                        'error' => $Exception->getMessage()
                    ]
                )
            );

            return;
        } catch (\Exception $Exception) {
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
                'message.ajax.client.update.success',
                [
                    'clientId' => $clientId
                ]
            )
        );
    },
    ['clientId', 'data'],
    'Permission::checkAdminUser'
);
