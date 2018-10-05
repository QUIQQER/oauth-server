<?php

namespace QUI\OAuth\Middleware;

use QUI;
use OAuth2;
use OAuth2\RequestInterface;
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

        $accessToken = $Request->query('access_token');

        if (empty($accessToken)) {
            $accessToken = $Request->request('access_token');
        }

        try {
            $clientData = OAuthClients::getOAuthClientByAccessToken($accessToken);
        } catch (\Exception $Exception) {
            QUI\System\Log::writeException($Exception);

            throw new InvalidRequestException(
                'system_error',
                'System error. Please contact an administrator.',
                500
            );
        }

        $scope = $this->parseScopeFromEndpoint(json_decode($clientData['scope_restrictions'], true), $endpoint);

        if (empty($scope)) {
            $this->throwInvalidScopeException();
        }

        $this->verifyScopePermission($clientData, $scope, $Request);
    }

    /**
     * Check if the current request is allowed to access the requested endpoint (scope)
     *
     * @param array $clientData - OAuth Client data
     * @param string $scope
     * @param RequestInterface $Request
     * @return void
     * @throws InvalidRequestException
     */
    protected function verifyScopePermission($clientData, $scope, RequestInterface $Request)
    {
        $scopeRestrictions = json_decode($clientData['scope_restrictions'], true);

        if (empty($scopeRestrictions[$scope])) {
            $this->throwInvalidScopeException();
        }

        $scopeSettings = $scopeRestrictions[$scope];

        if (!$scopeSettings['active']) {
            $this->throwInvalidScopeException();
        }

        if ($scopeSettings['unlimitedCalls']) {
            return;
        }

        // check access limits
        try {
            $table = QUI\OAuth\Setup::getTable('oauth_access_limits');
        } catch (\Exception $Exception) {
            QUI\System\Log::writeException($Exception);

            throw new InvalidRequestException(
                'system_error',
                'System error. Please contect an administrator.',
                500
            );
        }

        $result = QUI::getDataBase()->fetch([
            'select' => ['total_usage_count', 'interval_usage_count', 'first_usage', 'last_usage'],
            'from'   => $table,
            'where'  => [
                'client_id' => $clientData['client_id'],
                'scope'     => $scope
            ],
            'limit'  => 1
        ]);

        if (empty($result)) {
            $this->throwInvalidScopeException();
        }

        $now                = time();
        $data               = current($result);
        $writeToDatabase    = false;
        $firstUsage         = $data['first_usage'];
        $lastUsage          = $data['last_usage'];
        $totalUsageCount    = $data['total_usage_count'];
        $intervalUsageCount = $data['interval_usage_count'];
        $maxCalls           = $scopeSettings['maxCalls'];
        $maxCallsType       = $scopeSettings['maxCallsType'];
        $maxCallsExceeded   = false;

        // absolute call count restriction
        $totalUsageCount++;
        $intervalUsageCount++;

        if ($maxCallsType === 'absolute') {
            if ($intervalUsageCount > $maxCalls) {
                $maxCallsExceeded = true;
            } else {
                $writeToDatabase = true;
            }
        } else {
            // interval call count restriction
            $intervalSeconds = 60;

            switch ($maxCallsType) {
                case 'hour':
                    $intervalSeconds *= 60;
                    break;

                case 'day':
                    $intervalSeconds *= 60 * 24;
                    break;

                case 'month':
                    $intervalSeconds *= 60 * 24 * 30;
                    break;

                case 'year':
                    $intervalSeconds *= 60 * 24 * 365;
                    break;
            }

            if (!empty($lastUsage) && ($now - $lastUsage) > $intervalSeconds) {
                $intervalUsageCount = 1;
                $firstUsage         = $now;
                $lastUsage          = $now;
            }

            if ($intervalUsageCount > $maxCalls) {
                $maxCallsExceeded = true;
            } else {
                $writeToDatabase = true;
            }
        }

        if ($writeToDatabase) {
            QUI::getDataBase()->update($table, [
                'total_usage_count'    => $totalUsageCount,
                'interval_usage_count' => $intervalUsageCount,
                'first_usage'          => $firstUsage,
                'last_usage'           => $lastUsage
            ], [
                'client_id' => $clientData['client_id'],
                'scope'     => $scope
            ]);
        }

        if ($maxCallsExceeded) {
            throw new InvalidRequestException(
                'query_limit_reached',
                'You have exceeded the maximum number of calls ('.$maxCalls.') per time interval ('.$maxCallsType.').',
                403
            );
        }
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

    /**
     * Parses the OAuth2 scope from the requested REST API endpoint
     *
     * @param array $scopeRestrictions - OAuth client scope restrictions
     * @param string $endpoint
     * @return string|false - Scope name or false if scope could not be parsed
     */
    protected function parseScopeFromEndpoint($scopeRestrictions, $endpoint)
    {
        $requestsScope = false;

        foreach ($scopeRestrictions as $scope => $restrictions) {
            $parts        = explode('/', trim($scope, '/'));
            $literalParts = [];

            foreach ($parts as $part) {
                if (mb_strpos($part, '{') !== false) {
                    break;
                }

                $literalParts[] = $part;
            }

            $literalEndpoint = '/'.implode('/', $literalParts);

            if (mb_strpos($endpoint, $literalEndpoint) !== 0) {
                continue;
            }

            if (mb_substr_count($endpoint, '/') !== mb_substr_count($scope, '/')) {
                continue;
            }

            $requestsScope = $scope;
            break;
        }

        return $requestsScope;
    }

    /**
     * Throws InvalidRequestException for an invalid scope
     *
     * @throws InvalidRequestException
     */
    protected function throwInvalidScopeException()
    {
        throw new InvalidRequestException(
            'insufficient_scope',
            'The request requires higher privileges than provided by the access token.',
            403
        );
    }
}