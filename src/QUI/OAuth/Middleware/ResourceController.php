<?php

namespace QUI\OAuth\Middleware;

use QUI;
use OAuth2;
use OAuth2\RequestInterface;
use OAuth2\ResponseInterface;
use QUI\OAuth\Clients\Handler as OAuthClients;

class ResourceController extends \OAuth2\Controller\ResourceController
{
    /**
     * Verify a REST API request
     *
     * @param string $endpoint - The endpoint
     * @param RequestInterface $Request
     * @throws InvalidRequestException
     */
    public function verify($endpoint, RequestInterface $Request)
    {
        $VerificationResponse = new OAuth2\Response();

        // General verification (token and scope)
        parent::verifyResourceRequest($Request, $VerificationResponse);
        $this->parseErrorFromResponseAndThrowException($VerificationResponse);

        $queryData = $Request->getAllQueryParameters();

        try {
            $clientData = OAuthClients::getOAuthClientByAccessToken($queryData['access_token']);
        } catch (\Exception $Exception) {
            QUI\System\Log::writeException($Exception);

            throw new InvalidRequestException(
                'system_error',
                'System error. Please contect an administrator.',
                500
            );
        }

        $this->verifyEndpointPermission($clientData, $endpoint, $Request);
        $this->verifyAccessLimit($clientData, $endpoint, $Request);
    }

    /**
     * Check if the current request is allowed to access the requests endpoint
     *
     * @param array $clientData - OAuth Client data
     * @param string $endpoint
     * @param RequestInterface $Request
     * @throws InvalidRequestException
     */
    protected function verifyEndpointPermission($clientData, $endpoint, RequestInterface $Request)
    {
        
    }

    /**
     * Check if the current request is within its access limits
     *
     * @param array $clientData - OAuth Client data
     * @param string $endpoint
     * @param RequestInterface $Request
     * @throws InvalidRequestException
     */
    protected function verifyAccessLimit($clientData, $endpoint, RequestInterface $Request)
    {

    }

    /**
     * Checks if a Response contains an error and throws an InvalidRequestException if this
     * is the case
     *
     * @param OAuth2\Response $Response
     * @return void
     * @throws InvalidRequestException
     */
    protected function parseErrorFromResponseAndThrowException(OAuth2\Response $Response)
    {
        $responseBody = json_decode($Response->getResponseBody(), true);

        if (!empty($responseBody['error'])) {
            throw new InvalidRequestException(
                $responseBody['error'],
                empty($responseBody['error_description']) ? '' : $responseBody['error_description'],
                $Response->getStatusCode()
            );
        }
    }
}
