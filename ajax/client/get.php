<?php

use QUI\OAuth\ClientConfiguration;
use QUI\OAuth\Permission;

QUI::getAjax()->registerFunction(
    'package_quiqqer_oauth-server_ajax_client_get',
    /**
     * Return the client data
     *
     * @return array
     * @throws \QUI\Exception
     */
    function ($clientId) {
        $clientData = QUI\OAuth\Clients\Handler::getOAuthClient($clientId);
        $clientData['scope_restrictions'] = json_decode($clientData['scope_restrictions'], true);
        $clientData['authorization'] = null;

        if (ClientConfiguration::usesAuthorizationCode($clientData['grant_types'] ?? null)) {
            $resourceConfiguration = $clientData['allowed_resources'] ?? null;

            $clientData['authorization'] = [
                'redirectUris' => explode(' ', (string)$clientData['redirect_uri']),
                'resources' => ClientConfiguration::decodeResources($resourceConfiguration),
                'editable' => !ClientConfiguration::isDynamicRegistration($resourceConfiguration)
            ];
        }

        return $clientData;
    },
    ['clientId'],
    [
        'Permission::checkAdminUser',
        Permission::MANAGE_CLIENTS->value
    ]
);
