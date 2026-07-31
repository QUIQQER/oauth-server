<?php

namespace QUI\OAuth;

use OAuth2;
use Psr\Http\Message\ServerRequestInterface;
use QUI\REST\Response;

final class TokenEndpoint
{
    public function handle(ServerRequestInterface $Request): Response
    {
        $OAuthRequest = RequestFactory::fromPsr($Request);
        $OAuthResponse = new OAuth2\Response();
        $Storage = StorageFactory::create();

        try {
            $resource = $this->resolveResource($OAuthRequest, $Storage);
        } catch (\InvalidArgumentException $Exception) {
            $OAuthResponse->setError(400, 'invalid_target', $Exception->getMessage());

            return RestProvider::fromOAuthResponse($OAuthResponse);
        }

        Server::getInstance()->getOAuth2Server()->handleTokenRequest(
            $OAuthRequest,
            $OAuthResponse
        );

        if ($OAuthResponse->getStatusCode() === 200 && is_string($resource) && $resource !== '') {
            $parameters = $OAuthResponse->getParameters();
            $accessToken = $parameters['access_token'] ?? null;
            $refreshToken = $parameters['refresh_token'] ?? null;

            if (is_string($accessToken) && $accessToken !== '') {
                $Storage->setAccessTokenResource($accessToken, $resource);
            }

            if (is_string($refreshToken) && $refreshToken !== '') {
                $Storage->setRefreshTokenResource($refreshToken, $resource);
            }
        }

        return RestProvider::fromOAuthResponse($OAuthResponse);
    }

    public function revoke(ServerRequestInterface $Request): Response
    {
        $OAuthRequest = RequestFactory::fromPsr($Request);
        $OAuthResponse = new OAuth2\Response();
        $Storage = StorageFactory::create();
        $clientId = $this->getClientId($OAuthRequest);

        if (!$this->isAuthenticatedClient($OAuthRequest, $Storage, $clientId)) {
            $OAuthResponse->setError(401, 'invalid_client', 'Valid client authentication is required.');

            return RestProvider::fromOAuthResponse($OAuthResponse);
        }

        $token = $OAuthRequest->request('token');
        $hint = $OAuthRequest->request('token_type_hint');
        $tokenData = null;
        $tokenType = null;

        if (is_string($token) && $token !== '') {
            if ($hint === 'refresh_token') {
                $tokenData = $Storage->getRefreshToken($token);
                $tokenType = $tokenData === false ? null : 'refresh_token';
            } elseif ($hint === 'access_token') {
                $tokenData = $Storage->getAccessToken($token);
                $tokenType = $tokenData === false ? null : 'access_token';
            } else {
                $tokenData = $Storage->getAccessToken($token);
                $tokenType = $tokenData === false
                    ? 'refresh_token'
                    : 'access_token';
                $tokenData = $tokenData === false
                    ? $Storage->getRefreshToken($token)
                    : $tokenData;

                if ($tokenData === false) {
                    $tokenType = null;
                }
            }
        }

        if (is_array($tokenData) && !hash_equals((string)$tokenData['client_id'], $clientId)) {
            $OAuthResponse->setStatusCode(200);

            return RestProvider::fromOAuthResponse($OAuthResponse);
        }

        if (
            $tokenType === 'refresh_token'
            && is_string($token)
            && is_array($tokenData)
        ) {
            $Storage->revokeRefreshTokenFamily(
                (string)($tokenData['token_family_id'] ?? ''),
                $token
            );
            $OAuthResponse->setStatusCode(200);

            return RestProvider::fromOAuthResponse($OAuthResponse);
        }

        Server::getInstance()->getOAuth2Server()->handleRevokeRequest(
            $OAuthRequest,
            $OAuthResponse
        );

        return RestProvider::fromOAuthResponse($OAuthResponse);
    }

    private function resolveResource(OAuth2\Request $Request, Storage $Storage): ?string
    {
        $grantType = $Request->request('grant_type');
        $requestedResource = $Request->request('resource');
        $resource = null;
        $clientId = '';

        if ($grantType === 'authorization_code') {
            $code = $Request->request('code');
            $data = is_string($code) ? $Storage->getAuthorizationCode($code) : false;

            if (is_array($data)) {
                $resource = $data['resource'] ?? null;
                $clientId = (string)$data['client_id'];
            }
        } elseif ($grantType === 'refresh_token') {
            $refreshToken = $Request->request('refresh_token');
            $data = is_string($refreshToken) ? $Storage->getRefreshToken($refreshToken) : false;

            if (is_array($data)) {
                $resource = $data['resource'] ?? null;
                $clientId = (string)$data['client_id'];
            }
        } elseif ($grantType === 'client_credentials') {
            $clientId = $this->getClientId($Request);
        }

        if ($clientId !== '' && ($resource === null || $resource === '')) {
            $client = $Storage->getClientDetails($clientId);
            $resources = is_array($client)
                ? ClientConfiguration::decodeResources($client['allowed_resources'] ?? null)
                : [];

            if (count($resources) === 1) {
                $resource = $resources[0];
            }
        }

        if ($requestedResource !== null && !is_string($requestedResource)) {
            throw new \InvalidArgumentException('The resource parameter must be a URI string.');
        }

        if (
            is_string($requestedResource)
            && $requestedResource !== ''
            && (!is_string($resource) || !hash_equals($resource, $requestedResource))
        ) {
            throw new \InvalidArgumentException('The requested resource does not match the authorization grant.');
        }

        return is_string($resource) && $resource !== '' ? $resource : null;
    }

    private function isAuthenticatedClient(
        OAuth2\Request $Request,
        Storage $Storage,
        string $clientId
    ): bool {
        if ($clientId === '') {
            return false;
        }

        $clientSecret = $Request->headers('PHP_AUTH_PW');

        if (!is_string($clientSecret)) {
            $clientSecret = $Request->request('client_secret');
        }

        if (is_string($clientSecret) && $clientSecret !== '') {
            return $Storage->checkClientCredentials($clientId, $clientSecret);
        }

        return $Storage->isPublicClient($clientId);
    }

    private function getClientId(OAuth2\Request $Request): string
    {
        $clientId = $Request->headers('PHP_AUTH_USER');

        if (!is_string($clientId) || $clientId === '') {
            $clientId = $Request->request('client_id');
        }

        return is_string($clientId) ? $clientId : '';
    }
}
