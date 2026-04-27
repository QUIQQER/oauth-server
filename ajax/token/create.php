<?php

use QUI\OAuth\Permission;

QUI::$Ajax->registerFunction(
    'package_quiqqer_oauth-server_ajax_token_create',
    static function ($userId, $title = null): array | bool {
        try {
            $tokenData = (new QUI\OAuth\BackendController())->createPermanentAccessToken(
                QUI::getUsers()->get($userId),
                $title
            );
        } catch (QUI\OAuth\Exception $Exception) {
            QUI::getMessagesHandler()->addError(
                QUI::getLocale()->get(
                    'quiqqer/oauth-server',
                    'message.ajax.token.create.error',
                    [
                        'error' => $Exception->getMessage()
                    ]
                )
            );

            return false;
        } catch (Exception $Exception) {
            QUI\System\Log::writeException($Exception);

            QUI::getMessagesHandler()->addError(
                QUI::getLocale()->get(
                    'quiqqer/oauth-server',
                    'message.ajax.general_error'
                )
            );

            return false;
        }

        QUI::getMessagesHandler()->addSuccess(
            QUI::getLocale()->get(
                'quiqqer/oauth-server',
                'message.ajax.token.create.success',
                [
                    'title' => $tokenData['title']
                ]
            )
        );

        return $tokenData;
    },
    ['userId', 'title'],
    [
        'Permission::checkAdminUser',
        Permission::MANAGE_CLIENTS->value
    ]
);
