<?php

use QUI\OAuth\Permission;

QUI::$Ajax->registerFunction(
    'package_quiqqer_oauth-server_ajax_token_remove',
    static function ($clientId): bool {
        try {
            (new QUI\OAuth\BackendController())->deletePermanentAccessToken($clientId);
        } catch (QUI\OAuth\Exception $Exception) {
            QUI::getMessagesHandler()->addError(
                QUI::getLocale()->get(
                    'quiqqer/oauth-server',
                    'message.ajax.token.remove.error',
                    [
                        'error' => $Exception->getMessage()
                    ]
                )
            );

            return false;
        }

        QUI::getMessagesHandler()->addSuccess(
            QUI::getLocale()->get(
                'quiqqer/oauth-server',
                'message.ajax.token.remove.success',
                [
                    'clientId' => $clientId
                ]
            )
        );

        return true;
    },
    ['clientId'],
    [
        'Permission::checkAdminUser',
        Permission::MANAGE_CLIENTS->value
    ]
);
