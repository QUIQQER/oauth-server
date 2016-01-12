<?php

/**
 * This file contains QUI\OAuth\Serrver
 */
namespace QUI\OAuth;

use QUI;

/**
 * Class Server
 * oauth server for QUIQQER
 *
 * @package QUI\OAuth
 */
class Serrver
{
    /**
     * Serrver constructor.
     */
    public function __construct()
    {
        $this->Server = new \League\OAuth2\Server\AuthorizationServer;

        $this->Server->setSessionStorage(new SessionStorage());
        $this->Server->setAccessTokenStorage(new AccessTokenStorage);
        $this->Server->setClientStorage(new ClientStorage);
        $this->Server->setScopeStorage(new ScopeStorage);
        $this->Server->setAuthCodeStorage(new AuthCodeStorage);

        // Auth
        $PasswordGrant = new \League\OAuth2\Server\Grant\PasswordGrant();
        $PasswordGrant->setVerifyCredentialsCallback(function ($username, $password) {
            // implement logic here to validate a username and password,
            // return an ID if valid, return false otherwise

            QUI::getUsers()->getUserByName($username);
        });

        $this->Server->addGrantType($PasswordGrant);
    }


    public function oauth()
    {

    }


    public function signin()
    {

    }


    public function accessToken()
    {

    }
}
