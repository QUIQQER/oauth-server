<?php

use QUI\Utils\Security\Orthos;
use QUI\OAuth\Clients\Handler as OAuthClientsHandler;
use QUI\OAuth\Permission;

QUI::getAjax()->registerFunction(
    'package_quiqqer_oauth-server_ajax_client_create',
    /**
     * Create a new OAuth2 client
     *
     * @return string
     * @throws \QUI\Exception
     */
    function ($userId, $scopeSettings, $title = null, $authorization = ''): string {
        $title = Orthos::clear(is_string($title) ? $title : null);

        try {
            $User = QUI::getUsers()->get($userId);
            $scopes = Orthos::clearArray(json_decode($scopeSettings, true));

            if ($authorization === '') {
                $newClientId = OAuthClientsHandler::createOAuthClient($User, $scopes, $title);
            } else {
                $configuration = is_string($authorization) ? json_decode($authorization, true) : null;
                $redirectUris = $configuration['redirectUris'] ?? null;
                $resources = $configuration['resources'] ?? null;

                if (!is_array($redirectUris) || !is_array($resources)) {
                    throw new InvalidArgumentException('Redirect URIs and allowed resources must be lists.');
                }

                $newClientId = OAuthClientsHandler::createAuthorizationClient(
                    $User,
                    $scopes,
                    $title,
                    $redirectUris,
                    $resources
                );
            }
        } catch (InvalidArgumentException $Exception) {
            throw new QUI\Exception($Exception->getMessage(), 400);
        } catch (QUI\OAuth\Exception $Exception) {
            throw $Exception;
        } catch (Exception $Exception) {
            QUI\System\Log::writeException($Exception);

            throw new QUI\Exception(['quiqqer/oauth-server', 'message.ajax.general_error'], 500);
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

        return $newClientId;
    },
    ['userId', 'scopeSettings', 'title', 'authorization'],
    [
        'Permission::checkAdminUser',
        Permission::MANAGE_CLIENTS->value
    ]
);
