<?php

namespace QUITest\QUI\OAuth\Integration;

use GuzzleHttp\Psr7\Response;
use GuzzleHttp\Psr7\ServerRequest;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use PHPUnit\Framework\Attributes\PreserveGlobalState;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use QUI;
use QUI\OAuth\Clients\Handler;
use QUI\OAuth\Middleware\RestMiddleware;
use QUITest\QUI\OAuth\Support\OAuthDatabaseTestCase;

class RestMiddlewareValidationTest extends OAuthDatabaseTestCase
{
    #[RunInSeparateProcess]
    #[PreserveGlobalState(false)]
    public function testActualMiddlewareBypassesOauthAndUnprotectedRoutesAndAcceptsValidToken(): void
    {
        $scope = '/quiqqer_oauth_test';
        $clientId = self::createClient([
            $scope => [
                'active' => true,
                'unlimitedCalls' => true,
                'maxCalls' => 0,
                'maxCallsType' => 'absolute'
            ]
        ], true);
        $client = Handler::getOAuthClient($clientId);
        $Middleware = new RestMiddleware();
        $Handler = new class implements RequestHandlerInterface {
            public int $calls = 0;

            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                $this->calls++;

                return new Response(204);
            }
        };
        $RestConfig = QUI::getPackage('quiqqer/rest')->getConfig();
        $OAuthConfig = QUI::getPackage('quiqqer/oauth-server')->getConfig();
        $basePath = trim((string)$RestConfig->getValue('general', 'basePath'), '/');
        $urlPrefix = $basePath === '' ? '' : $basePath . '/';
        $previousProtectedScopes = $OAuthConfig->get('general', 'protected_scopes');

        try {
            $oauthResponse = $Middleware(
                (new ServerRequest('POST', '/oauth/token'))->withQueryParams([
                    '_url' => $urlPrefix . 'oauth/token'
                ]),
                $Handler
            );
            self::assertSame(204, $oauthResponse->getStatusCode());

            $OAuthConfig->setValue('general', 'protected_scopes', json_encode([$scope => false]));
            $unprotectedResponse = $Middleware(
                (new ServerRequest('GET', $scope))->withQueryParams([
                    '_url' => $urlPrefix . ltrim($scope, '/')
                ]),
                $Handler
            );
            self::assertSame(204, $unprotectedResponse->getStatusCode());

            $OAuthConfig->setValue('general', 'protected_scopes', json_encode([$scope => true]));
            $protectedQuery = ['_url' => $urlPrefix . ltrim($scope, '/')];

            $protectedResponse = $Middleware(
                (new ServerRequest('GET', $scope, [
                    'Authorization' => 'Bearer ' . $client['client_secret']
                ]))->withQueryParams($protectedQuery),
                $Handler
            );
            self::assertSame(204, $protectedResponse->getStatusCode());
            self::assertSame(3, $Handler->calls);
        } finally {
            $OAuthConfig->setValue('general', 'protected_scopes', $previousProtectedScopes);
        }
    }
}
