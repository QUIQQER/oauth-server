<?php

namespace QUI\OAuth;

use Psr\Http\Message\ServerRequestInterface;
use QUI;
use QUI\OAuth\Clients\Handler;
use QUI\REST\Response;

final class DynamicClientRegistrationEndpoint
{
    private const MAX_REQUEST_BYTES = 16_384;
    private const MAX_REDIRECT_URIS = 10;
    private const MAX_SCOPE_COUNT = 100;

    public static function isEnabled(): bool
    {
        $Config = QUI::getPackage('quiqqer/oauth-server')->getConfig();
        $value = $Config?->getValue(
            'general',
            'dynamic_client_registration'
        );

        return $value === true || $value === 1 || $value === '1';
    }

    public function handle(ServerRequestInterface $Request): Response
    {
        if (!self::isEnabled()) {
            return self::jsonResponse(
                404,
                [
                    'error' => 'invalid_client_metadata',
                    'error_description' => 'Dynamic client registration is disabled.'
                ]
            );
        }

        try {
            $metadata = self::parseMetadata($Request);
            $redirectUris = self::getRedirectUris($metadata);
            $grantTypes = self::getStringList(
                $metadata,
                'grant_types',
                ['authorization_code']
            );
            $responseTypes = self::getStringList(
                $metadata,
                'response_types',
                ['code']
            );
            $tokenEndpointAuthMethod = $metadata['token_endpoint_auth_method']
                ?? 'client_secret_basic';
            $applicationType = $metadata['application_type'] ?? 'native';
            $clientName = self::getClientName($metadata);
            $scopes = self::getScopes($metadata);

            self::validateProtocolMetadata(
                $grantTypes,
                $responseTypes,
                $tokenEndpointAuthMethod,
                $applicationType
            );

            $scopeSettings = [];

            foreach ($scopes as $scope) {
                $scopeSettings[$scope] = [
                    'active' => true,
                    'unlimitedCalls' => true,
                    'maxCalls' => 0,
                    'maxCallsType' => 'absolute'
                ];
            }

            $clientId = Handler::createDynamicAuthorizationClient(
                QUI::getUsers()->getSystemUser(),
                $scopeSettings,
                $clientName,
                $redirectUris,
                $grantTypes
            );
        } catch (DynamicClientRegistrationException $Exception) {
            return self::jsonResponse(
                $Exception->getStatusCode(),
                [
                    'error' => $Exception->getError(),
                    'error_description' => $Exception->getMessage()
                ]
            );
        } catch (\Throwable $Exception) {
            QUI\System\Log::writeException($Exception);

            return self::jsonResponse(
                500,
                [
                    'error' => 'server_error',
                    'error_description' => 'The OAuth client could not be registered.'
                ]
            );
        }

        $response = [
            'client_id' => $clientId,
            'client_id_issued_at' => time(),
            'client_name' => $clientName,
            'redirect_uris' => $redirectUris,
            'grant_types' => $grantTypes,
            'response_types' => $responseTypes,
            'token_endpoint_auth_method' => 'none',
            'application_type' => $applicationType
        ];

        if ($scopes !== []) {
            $response['scope'] = implode(' ', $scopes);
        }

        return self::jsonResponse(201, $response);
    }

    /**
     * @return array<string, mixed>
     */
    private static function parseMetadata(
        ServerRequestInterface $Request
    ): array {
        $contentType = strtolower(trim(explode(
            ';',
            $Request->getHeaderLine('Content-Type')
        )[0]));

        if ($contentType !== 'application/json') {
            throw new DynamicClientRegistrationException(
                'invalid_client_metadata',
                'Dynamic client registration requires an application/json request.'
            );
        }

        $declaredLength = $Request->getHeaderLine('Content-Length');

        if (
            $declaredLength !== ''
            && is_numeric($declaredLength)
            && (int)$declaredLength > self::MAX_REQUEST_BYTES
        ) {
            throw new DynamicClientRegistrationException(
                'invalid_client_metadata',
                'The client metadata request is too large.'
            );
        }

        $body = (string)$Request->getBody();

        if (strlen($body) > self::MAX_REQUEST_BYTES) {
            throw new DynamicClientRegistrationException(
                'invalid_client_metadata',
                'The client metadata request is too large.'
            );
        }

        try {
            $metadata = json_decode(
                $body,
                true,
                32,
                JSON_THROW_ON_ERROR
            );
        } catch (\JsonException) {
            throw new DynamicClientRegistrationException(
                'invalid_client_metadata',
                'The client metadata must be a valid JSON object.'
            );
        }

        if (!is_array($metadata) || array_is_list($metadata)) {
            throw new DynamicClientRegistrationException(
                'invalid_client_metadata',
                'The client metadata must be a JSON object.'
            );
        }

        return $metadata;
    }

    /**
     * @param array<string, mixed> $metadata
     * @return list<string>
     */
    private static function getRedirectUris(array $metadata): array
    {
        $redirectUris = $metadata['redirect_uris'] ?? null;

        if (
            !is_array($redirectUris)
            || !array_is_list($redirectUris)
            || $redirectUris === []
            || count($redirectUris) > self::MAX_REDIRECT_URIS
        ) {
            throw new DynamicClientRegistrationException(
                'invalid_redirect_uri',
                'Between one and ten redirect_uris must be registered.'
            );
        }

        try {
            $redirectUris = ClientConfiguration::validateRedirectUris(
                $redirectUris
            );
        } catch (\InvalidArgumentException $Exception) {
            throw new DynamicClientRegistrationException(
                'invalid_redirect_uri',
                $Exception->getMessage()
            );
        }

        if (strlen(implode(' ', $redirectUris)) > 2000) {
            throw new DynamicClientRegistrationException(
                'invalid_redirect_uri',
                'The registered redirect_uris are too long.'
            );
        }

        return array_values($redirectUris);
    }

    /**
     * @param array<string, mixed> $metadata
     * @param list<string> $default
     * @return list<string>
     */
    private static function getStringList(
        array $metadata,
        string $key,
        array $default
    ): array {
        $values = $metadata[$key] ?? $default;

        if (!is_array($values) || !array_is_list($values) || $values === []) {
            throw new DynamicClientRegistrationException(
                'invalid_client_metadata',
                $key . ' must be a non-empty array of strings.'
            );
        }

        foreach ($values as $value) {
            if (!is_string($value) || $value === '') {
                throw new DynamicClientRegistrationException(
                    'invalid_client_metadata',
                    $key . ' must be a non-empty array of strings.'
                );
            }
        }

        return array_values(array_unique($values));
    }

    /**
     * @param array<string, mixed> $metadata
     */
    private static function getClientName(array $metadata): string
    {
        $clientName = $metadata['client_name']
            ?? 'Dynamically registered OAuth client';

        if (
            !is_string($clientName)
            || trim($clientName) === ''
            || mb_strlen($clientName) > 250
            || preg_match('/[\x00-\x1F\x7F]/u', $clientName) === 1
        ) {
            throw new DynamicClientRegistrationException(
                'invalid_client_metadata',
                'client_name must be a non-empty string of at most 250 characters.'
            );
        }

        return trim($clientName);
    }

    /**
     * @param array<string, mixed> $metadata
     * @return list<string>
     */
    private static function getScopes(array $metadata): array
    {
        $scope = $metadata['scope'] ?? '';

        if (!is_string($scope) || strlen($scope) > 4000) {
            throw new DynamicClientRegistrationException(
                'invalid_client_metadata',
                'scope must be a space-separated string of OAuth scope tokens.'
            );
        }

        $scopes = trim($scope) === ''
            ? []
            : preg_split('/ +/', trim($scope));

        if (!is_array($scopes) || count($scopes) > self::MAX_SCOPE_COUNT) {
            throw new DynamicClientRegistrationException(
                'invalid_client_metadata',
                'No more than 100 OAuth scopes may be registered.'
            );
        }

        foreach ($scopes as $value) {
            if (preg_match('/^[\x21\x23-\x5B\x5D-\x7E]+$/D', $value) !== 1) {
                throw new DynamicClientRegistrationException(
                    'invalid_client_metadata',
                    'scope contains an invalid OAuth scope token.'
                );
            }
        }

        return array_values(array_unique($scopes));
    }

    /**
     * @param list<string> $grantTypes
     * @param list<string> $responseTypes
     */
    private static function validateProtocolMetadata(
        array $grantTypes,
        array $responseTypes,
        mixed $tokenEndpointAuthMethod,
        mixed $applicationType
    ): void {
        if (
            !in_array('authorization_code', $grantTypes, true)
            || array_diff(
                $grantTypes,
                ['authorization_code', 'refresh_token']
            ) !== []
        ) {
            throw new DynamicClientRegistrationException(
                'invalid_client_metadata',
                'Only authorization_code and refresh_token grant types are supported.'
            );
        }

        if ($responseTypes !== ['code']) {
            throw new DynamicClientRegistrationException(
                'invalid_client_metadata',
                'Only the code response type is supported.'
            );
        }

        if ($tokenEndpointAuthMethod !== 'none') {
            throw new DynamicClientRegistrationException(
                'invalid_client_metadata',
                'Dynamically registered clients must use token_endpoint_auth_method none.'
            );
        }

        if (
            !is_string($applicationType)
            || !in_array($applicationType, ['native', 'web'], true)
        ) {
            throw new DynamicClientRegistrationException(
                'invalid_client_metadata',
                'application_type must be native or web.'
            );
        }
    }

    /**
     * @param array<string, mixed> $data
     */
    private static function jsonResponse(int $status, array $data): Response
    {
        $body = json_encode(
            $data,
            JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
        );

        return new Response(
            $status,
            [
                'Content-Type' => 'application/json; charset=utf-8',
                'Cache-Control' => 'no-store',
                'Pragma' => 'no-cache'
            ],
            $body === false ? '{}' : $body
        );
    }
}
