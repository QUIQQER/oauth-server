<?php

/**
 * This file contains QUI\OAuth\Server
 */

namespace QUI\OAuth;

use QUI;
use OAuth2;
use QUI\OAuth\Middleware\ResourceController;

/**
 * Class Server
 *
 * QUIQQER OAuth2 Server (based on bshaffer/oauth2-server-php)
 */
class Server extends QUI\Utils\Singleton
{
    /**
     * @var OAuth2\Server
     */
    protected $OAuth2Server;

    /**
     * Server constructor.
     */
    public function __construct()
    {
        $Config = QUI::getPackage('quiqqer/oauth-server')->getConfig();

        // config
        $accessLifeTime = 3600;

        if ($Config->getValue('general', 'access_lifetime')) {
            $accessLifeTime = $Config->getValue('general', 'access_lifetime');
        }

        $config = [
            'access_lifetime'                   => $accessLifeTime,
            'use_jwt_access_tokens'             => false,
            'store_encrypted_token_string'      => true,
            'use_openid_connect'                => false,
            'id_lifetime'                       => 3600,
            'www_realm'                         => 'Service',
            'token_param_name'                  => 'access_token',
            'token_bearer_header_name'          => 'Bearer',
            'enforce_state'                     => true,
            'require_exact_redirect_uri'        => true,
            'allow_implicit'                    => false,
            'allow_credentials_in_request_body' => true,
            'allow_public_clients'              => true,
            'always_issue_new_refresh_token'    => false,
            'unset_refresh_token_after_use'     => true
        ];

        $Storage = new Storage(QUI::getDataBase()->getPDO());

        // Build server
        $this->OAuth2Server = new OAuth2\Server($Storage, $config);
        $this->OAuth2Server->addGrantType(new OAuth2\GrantType\ClientCredentials($Storage));

        $this->OAuth2Server->setResourceController(
            new ResourceController(
                new OAuth2\TokenType\Bearer([
                    'token_param_name'         => $config['token_param_name'],
                    'token_bearer_header_name' => $config['token_bearer_header_name']
                ]),
                $this->OAuth2Server->getStorage('access_token'),
                ['www_realm' => $config['www_realm']],
                $this->OAuth2Server->getScopeUtil()
            )
        );
    }

    /**
     * Return the OAuth2 server
     *
     * @return OAuth2\Server
     */
    public function getOAuth2Server()
    {
        return $this->OAuth2Server;
    }
}
