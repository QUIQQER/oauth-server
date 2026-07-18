<?php

namespace QUITest\QUI\OAuth\Integration;

use QUI;
use QUI\OAuth\BackendController;
use QUI\OAuth\EventHandler;
use QUI\OAuth\Exception as OAuthException;
use QUI\OAuth\FrontendController;
use QUI\OAuth\FrontendException;
use QUI\OAuth\FrontendUsers\Profile\Tokens;
use QUI\OAuth\Permission;
use QUI\OAuth\RestProvider;
use QUI\OAuth\Setup;
use QUITest\QUI\OAuth\Support\OAuthDatabaseTestCase;

class ControllerAndSetupTest extends OAuthDatabaseTestCase
{
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
        $body = $Control->getBody();
        self::assertStringContainsString('data-token-hidden="1"', $body);
        self::assertStringContainsString($tokens[0]['id'], $body);

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

        $schema = QUI\Utils\Text\XML::getDataBaseFromXml(dirname(__DIR__, 2) . '/database.xml');
        self::assertCount(7, $schema['globals']);
        $tablesByName = array_column($schema['globals'], null, 'suffix');
        self::assertSame('true', $tablesByName['oauth_clients']['field_attributes']['client_id']['primary']);
        self::assertSame('datetime', $tablesByName['oauth_access_tokens']['field_attributes']['expires']['type']);
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
        self::assertArrayHasKey('OAuth2Error', $specification['components']['responses']);
        self::assertSame(
            [['oAuth2' => []]],
            $specification['paths']['/example']['get']['security']
        );
        self::assertArrayHasKey('4XX', $specification['paths']['/example']['get']['responses']);
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

    public function testRequestEventHonorsActiveSetting(): void
    {
        $Config = QUI::getPackage('quiqqer/oauth-server')->getConfig();
        $previousActive = $Config->getValue('general', 'active');
        $Rewrite = $this->createMock(QUI\Rewrite::class);

        try {
            $Config->setValue('general', 'active', 0);
            EventHandler::onRequest($Rewrite, '/ignored');

            $Config->setValue('general', 'active', 1);
            EventHandler::onRequest($Rewrite, '/protected');
        } finally {
            $Config->setValue('general', 'active', $previousActive);
        }

        self::assertTrue(true);
    }
}
