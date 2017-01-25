<?php

namespace QUITest\QUI\OAuth\Clients;

use QUI;

/**
 * Class ConfigTest
 */
class HandlerTest extends \PHPUnit_Framework_TestCase
{
    public function testOAuthConnection()
    {
        $SystemUser    = QUI::getUsers()->getSystemUser();
        $oauthClientId = QUI\OAuth\Clients\Handler::createOAuthClient($SystemUser);

        $this->assertNotEmpty($oauthClientId);

        // make a oauth request
        $oauthClient = QUI\OAuth\Clients\Handler::getOAuthClient($oauthClientId, $SystemUser);

        $clientID     = $oauthClient['client_id'];
        $clientSecret = $oauthClient['client_secret'];

        $curl = "curl -u {$clientID}:{$clientSecret} ";
        $curl .= "http://rest.hen.pcsg/api/oauth/token -d 'grant_type=client_credentials'";

        $result = shell_exec($curl);
        $result = json_decode($result, true);

        $this->assertArrayHasKey('access_token', $result);

        if ($result['access_token']) {
            $accessKey = $result['access_token'];

            $result = shell_exec(
                "curl http://rest.hen.pcsg/api/oauth/authorize -d 'access_token={$accessKey}'"
            );

            $result = json_decode($result, true);

            $this->assertArrayHasKey('success', $result);
        }

        // delete the oauth clients
        QUI\OAuth\Clients\Handler::removeOAuthClient($clientID, $SystemUser);

        // check if the client doesn't exist
        try {
            QUI\OAuth\Clients\Handler::getOAuthClient($oauthClientId, $SystemUser);
            $this->assertTrue(false, 'OAuth Client still exists. Should not exists');
        } catch (QUI\OAuth\Exception $Exception) {
            $this->assertTrue(true);
        }

    }
}