<?php

namespace QUITest\QUI\OAuth\Clients;

use QUI;

/**
 * Class ConfigTest
 */
class HandlerTest extends \PHPUnit\Framework\TestCase
{
    public function testOAuthConnection()
    {
        $SystemUser    = QUI::getUsers()->getSystemUser();
        $oauthClientId = QUI\OAuth\Clients\Handler::createOAuthClient($SystemUser, [
            '/projects/{project}/{lang}/{id}' => [
                'active'         => true,
                'maxCalls'       => 2,
                'maxCallsType'   => 'minute',
                'unlimitedCalls' => false
            ]
        ]);

        $this->assertNotEmpty($oauthClientId);

        // make a oauth request
        $REST       = QUI\REST\Server::getInstance();
        $apiAddress = $REST->getAddress();

        $oauthClient = QUI\OAuth\Clients\Handler::getOAuthClient($oauthClientId);

        $clientID     = $oauthClient['client_id'];
        $clientSecret = $oauthClient['client_secret'];

        $curl = "curl -u {$clientID}:".escapeshellarg($clientSecret);
        $curl .= " {$apiAddress}oauth/token -d 'grant_type=client_credentials'";

        $result = shell_exec($curl);
        $result = json_decode($result, true);

        $this->assertArrayHasKey('access_token', $result);

        if ($result['access_token']) {
            $accessKey = $result['access_token'];

            $result = shell_exec(
                "curl {$apiAddress}projects/Basic/de/1 -d 'access_token={$accessKey}'"
            );

            $result = json_decode($result, true);

            \QUI\System\Log::writeRecursive("curl {$apiAddress}projects/Basic/de/1 -d 'access_token={$accessKey}'");
            \QUI\System\Log::writeRecursive($result);

            $this->assertArrayHasKey('success', $result);
        }

        // delete the oauth clients
        QUI\OAuth\Clients\Handler::removeOAuthClient($clientID);

        // check if the client doesn't exist
        try {
            QUI\OAuth\Clients\Handler::getOAuthClient($oauthClientId);
            $this->assertTrue(false, 'OAuth Client still exists. Should not exists');
        } catch (QUI\OAuth\Exception $Exception) {
            $this->assertTrue(true);
        }
    }
}
