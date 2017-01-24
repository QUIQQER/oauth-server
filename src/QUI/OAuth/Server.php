<?php

/**
 * This file contains QUI\OAuth\Server
 */
namespace QUI\OAuth;

use QUI;
use OAuth2;

/**
 * Class Server
 * oauth server for QUIQQER
 *
 * @package QUI\OAuth
 */
class Server
{
    /**
     * @var OAuth2\Server
     */
    protected $Server;

    /**
     * Serrver constructor.
     */
    public function __construct()
    {
        $Config = QUI::getPackage('quiqqer/oauth-server')->getConfig();

        // defaults
        $accessLifeTime                = 3600;
        $useJwtAccessTokens            = false;
        $storeEncryptedTokenString     = true;
        $useOpenidConnect              = false;
        $idLifetime                    = 3600;
        $wwwRealm                      = 'Service';
        $tokenParamName                = 'access_token';
        $tokenBearerHeaderName         = 'Bearer';
        $enforceState                  = true;
        $requireExactRedirectUri       = true;
        $allowImplicit                 = false;
        $allowCredentialsInRequestBody = true;
        $allowPublicClients            = true;
        $alwaysIssueNewRefreshToken    = false;
        $unsetRefreshTokenAfterUse     = true;

        // settings
        if ($Config->getValue('general', 'access_lifetime')) {
            $accessLifeTime = $Config->getValue('general', 'access_lifetime');
        }

        $Storage = new Storage();

        // GrantType / Permissions / Auth
        $this->Server = new OAuth2\Server(
            $Storage,
            [
                'access_lifetime'                   => $accessLifeTime,
                'use_jwt_access_tokens'             => $useJwtAccessTokens,
                'store_encrypted_token_string'      => $storeEncryptedTokenString,
                'use_openid_connect'                => $useOpenidConnect,
                'id_lifetime'                       => $idLifetime,
                'www_realm'                         => $wwwRealm,
                'token_param_name'                  => $tokenParamName,
                'token_bearer_header_name'          => $tokenBearerHeaderName,
                'enforce_state'                     => $enforceState,
                'require_exact_redirect_uri'        => $requireExactRedirectUri,
                'allow_implicit'                    => $allowImplicit,
                'allow_credentials_in_request_body' => $allowCredentialsInRequestBody,
                'allow_public_clients'              => $allowPublicClients,
                'always_issue_new_refresh_token'    => $alwaysIssueNewRefreshToken,
                'unset_refresh_token_after_use'     => $unsetRefreshTokenAfterUse
            ]
        );

        $this->Server->addGrantType(new OAuth2\GrantType\ClientCredentials($Storage));
    }

    /**
     * Return the oauth server
     *
     * @return OAuth2\Server
     */
    public function getServer()
    {
        return $this->Server;
    }
}
