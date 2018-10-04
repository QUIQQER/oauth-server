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

        try {
            $newClientId = OAuthClientsHandler::createOAuthClient(
                QUI::getUsers()->get((int)$userId),
                Orthos::clearArray(json_decode($scopeSettings, true)),
                $title
            );
        } catch (QUI\OAuth\Exception $Exception) {
            QUI::getMessagesHandler()->addError(
                QUI::getLocale()->get(
                    'quiqqer/oauth-server',
                    'message.ajax.client.create.error',
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
                'message.ajax.client.create.success',
                [
                    'clientId' => $newClientId
                ]
            )
        );
    },
    ['userId', 'scopeSettings', 'title'],
    'Permission::checkAdminUser'
);
