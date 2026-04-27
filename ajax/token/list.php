<?php

use QUI\OAuth\Permission;

QUI::$Ajax->registerFunction(
    'package_quiqqer_oauth-server_ajax_token_list',
    static function ($userId): array {
        try {
            return (new QUI\OAuth\BackendController())->getPermanentAccessTokens(
                QUI::getUsers()->get($userId)
            );
        } catch (QUI\OAuth\Exception $Exception) {
            QUI::getMessagesHandler()->addError($Exception->getMessage());
        } catch (Exception $Exception) {
            QUI\System\Log::writeException($Exception);

            QUI::getMessagesHandler()->addError(
                QUI::getLocale()->get(
                    'quiqqer/oauth-server',
                    'message.ajax.general_error'
                )
            );
        }

        return [];
    },
    ['userId'],
    [
        'Permission::checkAdminUser',
        Permission::MANAGE_CLIENTS->value
    ]
);
