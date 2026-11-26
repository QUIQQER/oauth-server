<?php

use QUI\Utils\Security\Orthos;
use QUI\OAuth\Permission;

QUI::getAjax()->registerFunction(
    'package_quiqqer_oauth-server_ajax_client_update',
    /**
     * Edit an Oauth2 client
     *
     * @param string $clientId
     * @param string $data (json_encoded array)
     * @return void
     */
    function ($clientId, $data): void {
        try {
            $submitted = is_string($data) ? json_decode($data, true) : null;

            if (!is_array($submitted)) {
                throw new InvalidArgumentException('Invalid client configuration.');
            }

            $clientSettings = Orthos::clearArray(array_diff_key($submitted, [
                'authorization' => true,
                'clientSecret' => true
            ]));

            // Redirect URIs, resources and the generated secret must retain their exact values.
            if (array_key_exists('authorization', $submitted)) {
                $clientSettings['authorization'] = $submitted['authorization'];
            }

            $clientSettings['clientSecret'] = $submitted['clientSecret'] ?? null;

            QUI\OAuth\Clients\Handler::updateOAuthClient($clientId, $clientSettings);
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
                'message.ajax.client.update.success',
                [
                    'clientId' => $clientId
                ]
            )
        );
    },
    ['clientId', 'data'],
    [
        'Permission::checkAdminUser',
        Permission::MANAGE_CLIENTS->value
    ]
);
