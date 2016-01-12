<?php

/**
 * This file contains QUI\OAuth\Serrver
 */
namespace QUI\OAuth;

use QUI;
use League\OAuth2\Server\Entity\AccessTokenEntity;
use League\OAuth2\Server\Entity\AuthCodeEntity;
use League\OAuth2\Server\Entity\ScopeEntity;
use League\OAuth2\Server\Entity\SessionEntity;
use League\OAuth2\Server\Storage\AbstractStorage;
use League\OAuth2\Server\Storage\SessionInterface;

/**
 * Class SessionStorage
 *
 * @package QUI\OAuth
 */
class SessionStorage extends AbstractStorage implements SessionInterface
{
    /**
     * {@inheritdoc}
     */
    public function getByAccessToken(AccessTokenEntity $accessToken)
    {
//
//        $result = Capsule::table('oauth_sessions')
//            ->select([
//                'oauth_sessions.id',
//                'oauth_sessions.owner_type',
//                'oauth_sessions.owner_id',
//                'oauth_sessions.client_id',
//                'oauth_sessions.client_redirect_uri'
//            ])
//            ->join('oauth_access_tokens', 'oauth_access_tokens.session_id', '=', 'oauth_sessions.id')
//            ->where('oauth_access_tokens.access_token', $accessToken->getId())
//            ->get();

        $sessionTable     = Package::getDataBaseTableNames('oauth_sessions');
        $accessTokenTable = Package::getDataBaseTableNames('oauth_access_tokens');

        $result = QUI::getDataBase()->fetch(array(
            'from' => array($sessionTable, $accessTokenTable),
            'where' => array(
                $accessTokenTable . '.access_token' => $accessToken->getId(),
                $accessTokenTable . '.session_id' => $sessionTable . '.id'
            )
        ));

        if (count($result) === 1) {
            $session = new SessionEntity($this->server);
            $session->setId($result[0]['id']);
            $session->setOwner($result[0]['owner_type'], $result[0]['owner_id']);

            return $session;
        }

        return null;
    }

    /**
     * {@inheritdoc}
     */
    public function getByAuthCode(AuthCodeEntity $authCode)
    {
//        $result = Capsule::table('oauth_sessions')
//            ->select([
//                'oauth_sessions.id',
//                'oauth_sessions.owner_type',
//                'oauth_sessions.owner_id',
//                'oauth_sessions.client_id',
//                'oauth_sessions.client_redirect_uri'
//            ])
//            ->join('oauth_auth_codes', 'oauth_auth_codes.session_id', '=', 'oauth_sessions.id')
//            ->where('oauth_auth_codes.auth_code', $authCode->getId())
//            ->get();
        $sessionTable   = Package::getDataBaseTableNames('oauth_sessions');
        $authCodesTable = Package::getDataBaseTableNames('oauth_auth_codes');

        $result = QUI::getDataBase()->fetch(array(
            'from' => array($sessionTable, $authCodesTable),
            'where' => array(
                $authCodesTable . '.auth_code' => $authCode->getId(),
                $authCodesTable . '.session_id' => $sessionTable . '.id'
            )
        ));

        if (count($result) === 1) {
            $session = new SessionEntity($this->server);
            $session->setId($result[0]['id']);
            $session->setOwner($result[0]['owner_type'], $result[0]['owner_id']);

            return $session;
        }

        return null;
    }

    /**
     * {@inheritdoc}
     */
    public function getScopes(SessionEntity $session)
    {
//        $result = Capsule::table('oauth_sessions')
//            ->select('oauth_scopes .*')
//            ->join('oauth_session_scopes', 'oauth_sessions . id', ' = ', 'oauth_session_scopes . session_id')
//            ->join('oauth_scopes', 'oauth_scopes . id', ' = ', 'oauth_session_scopes . scope')
//            ->where('oauth_sessions . id', $session->getId())
//            ->get();

        $sessionTable      = Package::getDataBaseTableNames('oauth_sessions');
        $authScopeTable    = Package::getDataBaseTableNames('oauth_scopes');
        $sessionScopeTable = Package::getDataBaseTableNames('oauth_session_scopes');

        $result = QUI::getDataBase()->fetch(array(
            'from' => array($sessionTable, $authScopeTable, $sessionScopeTable),
            'where' => array(
                $sessionTable . '.id' => $session->getId(),
                $sessionTable . '.id' => $sessionScopeTable . '.session_id',
                $authScopeTable . '.id' => $sessionScopeTable . '.scope'
            )
        ));

        $scopes = [];

        foreach ($result as $scope) {
            $scopes[] = (new ScopeEntity($this->server))->hydrate([
                'id' => $scope['id'],
                'description' => $scope['description'],
            ]);
        }

        return $scopes;
    }

    /**
     * {@inheritdoc}
     */
    public function create($ownerType, $ownerId, $clientId, $clientRedirectUri = null)
    {
        QUI::getDataBase()->insert(
            Package::getDataBaseTableNames('oauth_sessions'),
            array(
                'owner_type' => $ownerType,
                'owner_id' => $ownerId,
                'client_id' => $clientId
            )
        );

        return QUI::getDataBase()->getPDO()->lastInsertId();
    }

    /**
     * {@inheritdoc}
     */
    public function associateScope(SessionEntity $session, ScopeEntity $scope)
    {
        QUI::getDataBase()->insert(
            Package::getDataBaseTableNames('oauth_session_scopes'),
            array(
                'session_id' => $session->getId(),
                'scope' => $scope->getId(),
            )
        );
    }
}
