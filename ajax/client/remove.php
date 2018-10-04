<?php

/**
 * Create a oauth client entry
 *
 * @return string
 * @throws \QUI\Exception
 */
QUI::$Ajax->registerFunction(
    'package_quiqqer_oauth-server_ajax_client_remove',
    function ($clientId) {
        try {
            QUI\OAuth\Clients\Handler::removeOAuthClient($clientId);
        } catch (QUI\OAuth\Exception $Exception) {
            QUI::getMessagesHandler()->addError(
                QUI::getLocale()->get(
                    'quiqqer/oauth-server',
                    'message.ajax.client.remove.error',
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
                'message.ajax.client.remove.success',
                [
                    'clientId' => $clientId
                ]
            )
        );
    },
    array('clientId')
);
