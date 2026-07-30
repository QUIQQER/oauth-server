<?php

namespace QUITest\QUI\OAuth\Integration;

use GuzzleHttp\Psr7\ServerRequest;
use QUI;
use QUI\OAuth\BackendController;
use QUI\OAuth\EventHandler;
use QUI\OAuth\Exception as OAuthException;
use QUI\OAuth\FrontendController;
use QUI\OAuth\FrontendException;
use QUI\OAuth\FrontendUsers\Profile\Tokens;
use QUI\OAuth\Metadata;
use QUI\OAuth\Permission;
use QUI\OAuth\RestProvider;
use QUI\OAuth\Setup;
use QUITest\QUI\OAuth\Support\OAuthDatabaseTestCase;

class ControllerAndSetupTest extends OAuthDatabaseTestCase
{
    public function testOAuthMiddlewareIsInitializedOnlyForRestPaths(): void
    {
        $Method = new \ReflectionMethod(EventHandler::class, 'isRestRequestPath');

        self::assertTrue($Method->invoke(null, '/api', '/api/'));
        self::assertTrue($Method->invoke(null, '/api/v2/iban/validate', '/api/'));
        self::assertFalse($Method->invoke(null, '/', '/api/'));
        self::assertFalse($Method->invoke(null, '/apiary', '/api/'));
        self::assertFalse($Method->invoke(null, '/api/v2', ''));
    }

    public function testBackendAndFrontendPermanentTokenWorkflows(): void
    {
        $SystemUser = QUI::getUsers()->getSystemUser();
        $Backend = new BackendController();
        $backendToken = $Backend->createPermanentAccessToken(
            $SystemUser,
            self::TEST_PREFIX . '<b>backend</b>'
        );

        self::assertNotSame('', $backendToken['id']);
        self::assertNotSame('', $backendToken['token']);
        self::assertStringNotContainsString('<b>', $backendToken['title']);
        self::assertNotSame('', $backendToken['createDate']);
        self::assertNotEmpty($Backend->getPermanentAccessTokens($SystemUser));
        $Backend->deletePermanentAccessToken($backendToken['id']);
        self::assertSame([], $Backend->getPermanentAccessTokens($SystemUser));

        $Frontend = new FrontendController();
        $frontendSecret = $Frontend->createPermanentAccessToken(
            $SystemUser,
            self::TEST_PREFIX . 'frontend'
        );
        self::assertNotSame('', $frontendSecret);

        $frontendTokens = $Frontend->getPermanentAccessTokens($SystemUser);
        self::assertCount(1, $frontendTokens);
        self::assertContains($frontendSecret, array_column($frontendTokens, 'token'));

        $frontendToken = current(array_filter(
            $frontendTokens,
            static fn(array $token): bool => $token['token'] === $frontendSecret
        ));
        self::assertIsArray($frontendToken);
        $Frontend->deletePermanentAccessToken($SystemUser, $frontendToken['id']);
        self::assertSame([], $Backend->getPermanentAccessTokens($SystemUser));
    }

    public function testBackendRejectsDeletionOfOrdinaryClient(): void
    {
        $clientId = self::createClient();

        $this->expectException(OAuthException::class);
        (new BackendController())->deletePermanentAccessToken($clientId);
    }

    public function testPermanentTokenLimitsAndPermissionFailuresAreRejected(): void
    {
        $SystemUser = QUI::getUsers()->getSystemUser();
        $existingClientId = self::createClient([], true);

        try {
            (new BackendController())->createPermanentAccessToken($SystemUser);
            self::fail('Backend token limit must be enforced.');
        } catch (OAuthException $Exception) {
            self::assertStringNotContainsString('client_secret', $Exception->getMessage());
        }

        try {
            (new FrontendController())->createPermanentAccessToken($SystemUser);
            self::fail('Frontend token limit must be enforced.');
        } catch (FrontendException $Exception) {
            self::assertStringNotContainsString('client_secret', $Exception->getMessage());
        }

        QUI\OAuth\Clients\Handler::removeOAuthClient($existingClientId);

        try {
            (new FrontendController())->createPermanentAccessToken(QUI::getUsers()->getNobody());
            self::fail('Unauthenticated users must not create tokens.');
        } catch (FrontendException $Exception) {
            self::assertStringNotContainsString('token=', $Exception->getMessage());
        }
    }

    public function testFrontendRejectsTokenOwnedByAnotherUser(): void
    {
        $clientId = self::createClient([], true);
        self::getConnection()->update(
            QUI\Utils\Doctrine::quoteIdentifier(Setup::getTable('oauth_clients')),
            ['user_id' => 99999999],
            ['client_id' => $clientId]
        );

        $this->expectException(FrontendException::class);
        (new FrontendController())->deletePermanentAccessToken(
            QUI::getUsers()->getSystemUser(),
            $clientId
        );
    }

    public function testFrontendProfileControlCreatesRendersAndDeletesTokens(): void
    {
        $SystemUser = QUI::getUsers()->getSystemUser();
        $Control = new Tokens(['User' => $SystemUser]);

        QUI::getRequest()->request->replace([
            'oauthTokenAction' => 'create',
            'tokenTitle' => self::TEST_PREFIX . 'profile'
        ]);
        $Control->onSave();

        $tokens = (new FrontendController())->getPermanentAccessTokens($SystemUser);
        self::assertCount(1, $tokens);

        self::getConnection()->update(
            QUI\Utils\Doctrine::quoteIdentifier(Setup::getTable('oauth_clients')),
            [
                'name' => '<script>alert(1)</script>',
                'client_secret' => '" onmouseover="alert(1)'
            ],
            ['client_id' => $tokens[0]['id']]
        );

        $body = $Control->getBody();
        self::assertStringContainsString('data-token-hidden="1"', $body);
        self::assertStringContainsString($tokens[0]['id'], $body);
        self::assertStringNotContainsString('<script>alert(1)</script>', $body);
        self::assertStringContainsString('&lt;script&gt;alert(1)&lt;/script&gt;', $body);
        self::assertStringNotContainsString('data-token-value="" onmouseover=', $body);

        QUI::getRequest()->request->replace([
            'oauthTokenAction' => 'delete',
            'oauthTokenId' => $tokens[0]['id']
        ]);
        $Control->onSave();
        self::assertSame([], (new FrontendController())->getPermanentAccessTokens($SystemUser));
    }

    public function testPermissionEnumUsesCurrentAndExplicitUsers(): void
    {
        $SystemUser = QUI::getUsers()->getSystemUser();

        self::assertTrue(Permission::MANAGE_CLIENTS->has($SystemUser));
        Permission::MANAGE_CLIENTS->check($SystemUser);
        self::assertTrue(Permission::MANAGE_CLIENTS->has());
    }

    public function testSetupAllowlistSchemaAndIdempotentExecution(): void
    {
        self::assertSame(QUI::getDBTableName('oauth_clients'), Setup::getTable('oauth_clients'));
        self::assertCount(6, Setup::getClientTables());

        Setup::execute();

        foreach (Setup::getClientTables() as $table) {
            self::assertTrue(QUI::getSchemaManager()->tablesExist([$table]));
        }

        $clientColumns = QUI::getSchemaManager()->listTableColumns(Setup::getTable('oauth_clients'));
        self::assertArrayHasKey('client_id', $clientColumns);
        self::assertArrayHasKey('client_secret_is_token', $clientColumns);
        self::assertArrayHasKey('allowed_resources', $clientColumns);

        $schema = QUI\Utils\Text\XML::getDataBaseFromXml(dirname(__DIR__, 2) . '/database.xml');
        self::assertCount(7, $schema['globals']);
        $tablesByName = array_column($schema['globals'], null, 'suffix');
        self::assertSame('true', $tablesByName['oauth_clients']['field_attributes']['client_id']['primary']);
        self::assertSame('datetime', $tablesByName['oauth_access_tokens']['field_attributes']['expires']['type']);
        self::assertSame('string', $tablesByName['oauth_access_tokens']['field_attributes']['resource']['type']);
        self::assertSame(['client_id', 'scope'], $tablesByName['oauth_access_limits']['primary']);

        $this->expectException(QUI\Exception::class);
        Setup::getTable('untrusted_table_name');
    }

    public function testRestProviderAndOpenApiExtensionPoints(): void
    {
        $Provider = new RestProvider();
        self::assertSame('OAuthServer', $Provider->getName());
        self::assertFalse($Provider->getOpenApiDefinitionFile());
        self::assertNotSame('', $Provider->getTitle());
        self::assertNotSame('', $Provider->getTitle(QUI::getLocale()));

        $RestServer = new QUI\REST\Server(['basePath' => '/api']);
        $Provider->register($RestServer);
        $routePatterns = array_map(
            static fn($Route): string => $Route->getPattern(),
            $RestServer->getSlim()->getRouteCollector()->getRoutes()
        );
        self::assertContains('/oauth/token', $routePatterns);
        self::assertContains('/oauth/authorize', $routePatterns);
        self::assertContains('/oauth/revoke', $routePatterns);
        self::assertContains('/oauth/register', $routePatterns);
        self::assertNotContains('/.well-known/oauth-authorization-server', $routePatterns);
        self::assertNotContains('/.well-known/oauth-protected-resource', $routePatterns);
        self::assertContains('/quiqqer_oauth_test', $routePatterns);

        $specification = [
            'paths' => [
                '/example' => [
                    'get' => ['responses' => []]
                ]
            ]
        ];

        $Config = QUI::getPackage('quiqqer/oauth-server')->getConfig();
        $previousActive = $Config->getValue('general', 'active');

        try {
            $Config->setValue('general', 'active', 1);
            EventHandler::onQuiqqerRestLoadOpenApiSpecification('test', $specification);
        } finally {
            $Config->setValue('general', 'active', $previousActive);
        }

        self::assertSame(
            'oauth2',
            $specification['components']['securitySchemes']['oAuth2']['type']
        );
        self::assertArrayHasKey(
            'authorizationCode',
            $specification['components']['securitySchemes']['oAuth2']['flows']
        );
        self::assertArrayHasKey('OAuth2Error', $specification['components']['responses']);
        self::assertSame(
            [['oAuth2' => []]],
            $specification['paths']['/example']['get']['security']
        );
        self::assertArrayHasKey('4XX', $specification['paths']['/example']['get']['responses']);
    }

    public function testRestProviderIssuesTokenFromPsrRequest(): void
    {
        $clientId = self::createClient();
        QUI\OAuth\Clients\Handler::updateOAuthClient($clientId, [
            'clientSecret' => 'secret:with:multiple:colons'
        ]);
        $client = QUI\OAuth\Clients\Handler::getOAuthClient($clientId);
        $RestServer = new QUI\REST\Server(['basePath' => '/api']);
        (new RestProvider())->register($RestServer);

        $_GET = [];
        $_POST = [];
        $_REQUEST = [];
        unset(
            $_SERVER['HTTP_AUTHORIZATION'],
            $_SERVER['PHP_AUTH_USER'],
            $_SERVER['PHP_AUTH_PW']
        );

        $Request = (new ServerRequest(
            'POST',
            '/api/oauth/token',
            [
                'Authorization' => 'Basic ' . base64_encode(
                    $clientId . ':' . $client['client_secret']
                ),
                'Content-Type' => 'application/x-www-form-urlencoded'
            ]
        ))->withParsedBody([
            'grant_type' => 'client_credentials'
        ]);

        $Response = $RestServer->getSlim()->handle($Request);
        $payload = json_decode((string)$Response->getBody(), true);
        $oauthError = is_array($payload) && isset($payload['error'])
            ? (string)$payload['error']
            : 'unknown_oauth_error';

        self::assertSame(200, $Response->getStatusCode(), $oauthError);
        self::assertIsArray($payload);
        self::assertArrayHasKey('access_token', $payload);
        self::assertSame('Bearer', $payload['token_type']);
    }

    public function testPackageSetupHandlerIgnoresOtherPackagesAndHandlesOwnPackage(): void
    {
        $OtherPackage = $this->createMock(QUI\Package\Package::class);
        $OtherPackage->method('getName')->willReturn('example/other');
        EventHandler::onPackageSetup($OtherPackage);
        EventHandler::onPackageInstall($OtherPackage);

        EventHandler::onPackageSetup(QUI::getPackage('quiqqer/oauth-server'));
        self::assertTrue(QUI::getSchemaManager()->tablesExist([Setup::getTable('oauth_clients')]));
    }

    public function testOnRequestEventHonorsActiveSettingAndRestPath(): void
    {
        $Config = QUI::getPackage('quiqqer/oauth-server')->getConfig();
        $previousActive = $Config->getValue('general', 'active');
        $previousRequest = QUI::$Request;
        $ServerProperty = new \ReflectionProperty(QUI\REST\Server::class, 'currentInstance');
        $previousServer = $ServerProperty->getValue();
        $Rewrite = $this->createMock(QUI\Rewrite::class);
        $InactiveSlim = $this->createMock(\Slim\App::class);
        $InactiveSlim->expects($this->never())->method('add');
        $InactiveServer = $this->createMock(QUI\REST\Server::class);
        $InactiveServer->method('getSlim')->willReturn($InactiveSlim);
        $ActiveSlim = $this->createMock(\Slim\App::class);
        $ActiveSlim
            ->expects($this->once())
            ->method('add')
            ->with($this->isInstanceOf(QUI\OAuth\Middleware\RestMiddleware::class))
            ->willReturnSelf();
        $ActiveServer = $this->createMock(QUI\REST\Server::class);
        $ActiveServer->method('getSlim')->willReturn($ActiveSlim);

        try {
            $ServerProperty->setValue(null, $InactiveServer);
            QUI::$Request = \Symfony\Component\HttpFoundation\Request::create('/api/v2/example');
            $Config->setValue('general', 'active', 0);
            EventHandler::onRequest($Rewrite, 'api/v2/example');

            $Config->setValue('general', 'active', 1);
            QUI::$Request = \Symfony\Component\HttpFoundation\Request::create('/ordinary-page');
            EventHandler::onRequest($Rewrite, 'ordinary-page');

            $ServerProperty->setValue(null, $ActiveServer);
            QUI::$Request = \Symfony\Component\HttpFoundation\Request::create('/api/v2/example');
            EventHandler::onRequest($Rewrite, 'api/v2/example');
        } finally {
            $Config->setValue('general', 'active', $previousActive);
            QUI::$Request = $previousRequest;
            $ServerProperty->setValue(null, $previousServer);
        }

        $Events = simplexml_load_file(dirname(__DIR__, 2) . '/events.xml');
        self::assertInstanceOf(\SimpleXMLElement::class, $Events);
        $eventNames = [];

        foreach ($Events->event as $Event) {
            $eventNames[(string)$Event['fire']] = (string)$Event['on'];
        }

        self::assertSame('onRequest', $eventNames['\QUI\OAuth\EventHandler::onRequest']);
        self::assertArrayNotHasKey('\QUI\OAuth\EventHandler::onRestInit', $eventNames);
    }

    public function testDiscoveryIsHandledAtOriginRootOutsideSlim(): void
    {
        $Server = new QUI\REST\Server([
            'basePath' => '/api/',
            'baseHost' => '/'
        ]);
        $Request = \Symfony\Component\HttpFoundation\Request::create(
            'https://project.example/.well-known/oauth-authorization-server'
        );
        $Response = EventHandler::getDiscoveryResponse(
            $Request,
            '.well-known/oauth-authorization-server',
            $Server
        );

        self::assertInstanceOf(\Symfony\Component\HttpFoundation\JsonResponse::class, $Response);
        self::assertSame(200, $Response->getStatusCode());
        $metadata = json_decode((string)$Response->getContent(), true);
        self::assertIsArray($metadata);
        self::assertSame('https://project.example/api', $metadata['issuer']);
        self::assertSame(
            'https://project.example/api/oauth/authorize',
            $metadata['authorization_endpoint']
        );
        self::assertArrayNotHasKey('scopes_supported', $metadata);

        $protectedResource = Metadata::protectedResource(
            $Server,
            'https://project.example'
        );
        self::assertArrayHasKey('scopes_supported', $protectedResource);

        $previousRequest = QUI::$Request;

        try {
            QUI::$Request = \Symfony\Component\HttpFoundation\Request::create(
                'https://project.example/mcp'
            );
            $metadataFromCurrentRequest = Metadata::authorizationServer($Server);
        } finally {
            QUI::$Request = $previousRequest;
        }

        self::assertSame(
            'https://project.example/api/oauth/authorize',
            $metadataFromCurrentRequest['authorization_endpoint']
        );

        self::assertNull(EventHandler::getDiscoveryResponse(
            $Request,
            'api/.well-known/oauth-authorization-server',
            $Server
        ));

        $MethodNotAllowed = EventHandler::getDiscoveryResponse(
            \Symfony\Component\HttpFoundation\Request::create(
                'https://project.example/.well-known/oauth-protected-resource',
                'POST'
            ),
            '/.well-known/oauth-protected-resource',
            $Server
        );
        self::assertInstanceOf(\Symfony\Component\HttpFoundation\JsonResponse::class, $MethodNotAllowed);
        self::assertSame(405, $MethodNotAllowed->getStatusCode());
        self::assertSame('GET', $MethodNotAllowed->headers->get('Allow'));
    }
}
