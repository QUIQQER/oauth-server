<?php

namespace QUI\OAuth;

use OAuth2\Controller\AuthorizeController;
use OAuth2\RequestInterface;
use OAuth2\ResponseInterface;
use QUI\OAuth\Clients\Handler;
use QUI\REST\Server as RestServer;

final class AuthorizationController extends AuthorizeController
{
    private ?string $codeChallenge = null;
    private ?string $codeChallengeMethod = null;
    private ?string $resource = null;

    public function validateAuthorizeRequest(RequestInterface $request, ResponseInterface $response): bool
    {
        if (!parent::validateAuthorizeRequest($request, $response)) {
            return false;
        }

        $codeChallenge = $request->query('code_challenge', $request->request('code_challenge'));
        $codeChallengeMethod = $request->query(
            'code_challenge_method',
            $request->request('code_challenge_method')
        );

        if (
            !is_string($codeChallenge)
            || preg_match('/^[A-Za-z0-9_-]{43}$/', $codeChallenge) !== 1
        ) {
            return $this->setRedirectError(
                $response,
                'invalid_request',
                'A valid PKCE code challenge is required.'
            );
        }

        if ($codeChallengeMethod !== 'S256') {
            return $this->setRedirectError(
                $response,
                'invalid_request',
                'Only the PKCE S256 code challenge method is supported.'
            );
        }

        $clientId = $this->getClientId();
        $client = $this->clientStorage->getClientDetails($clientId);
        $allowedResources = ClientConfiguration::decodeResources(
            $client['allowed_resources'] ?? null
        );
        $requestedResource = $request->query('resource', $request->request('resource'));
        $isDynamicRegistration = ClientConfiguration::isDynamicRegistration(
            $client['allowed_resources'] ?? null
        );

        if ($isDynamicRegistration && $allowedResources === []) {
            if (!is_string($requestedResource) || $requestedResource === '') {
                return $this->setRedirectError(
                    $response,
                    'invalid_target',
                    'The resource parameter is required for dynamically registered clients.'
                );
            }

            try {
                $bound = Handler::bindDynamicAuthorizationClientResource(
                    $clientId,
                    $requestedResource,
                    Metadata::resource(RestServer::getCurrentInstance())
                );
            } catch (\InvalidArgumentException) {
                $bound = false;
            } catch (\Throwable $Exception) {
                \QUI\System\Log::writeException($Exception);
                $bound = false;
            }

            if (!$bound) {
                return $this->setRedirectError(
                    $response,
                    'invalid_target',
                    'The requested resource cannot be registered for this client.'
                );
            }

            $allowedResources = [$requestedResource];
        }

        if ($requestedResource === null || $requestedResource === '') {
            if (count($allowedResources) !== 1) {
                return $this->setRedirectError(
                    $response,
                    'invalid_target',
                    'The resource parameter is required for this client.'
                );
            }

            $requestedResource = $allowedResources[0];
        }

        if (
            !is_string($requestedResource)
            || !in_array($requestedResource, $allowedResources, true)
        ) {
            return $this->setRedirectError(
                $response,
                'invalid_target',
                'The requested resource is not registered for this client.'
            );
        }

        $this->codeChallenge = $codeChallenge;
        $this->codeChallengeMethod = $codeChallengeMethod;
        $this->resource = $requestedResource;

        return true;
    }

    /**
     * @param RequestInterface $request
     * @param ResponseInterface $response
     * @param mixed $user_id
     * @return array<string, mixed>
     */
    protected function buildAuthorizeParameters($request, $response, $user_id): array
    {
        $parameters = parent::buildAuthorizeParameters($request, $response, $user_id);
        $parameters['code_challenge'] = $this->codeChallenge;
        $parameters['code_challenge_method'] = $this->codeChallengeMethod;
        $parameters['resource'] = $this->resource;

        return $parameters;
    }

    private function setRedirectError(
        ResponseInterface $response,
        string $error,
        string $description
    ): false {
        $response->setRedirect(
            302,
            $this->getRedirectUri(),
            (string)$this->getState(),
            $error,
            $description
        );

        return false;
    }
}
