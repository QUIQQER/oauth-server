<?php

namespace QUI\OAuth;

use QUI;
use OAuth2;

/**
 * Class Storage
 *
 * QUIQQER PDO Storage for bshaffer/oauth2-server-php
 */
class Storage extends OAuth2\Storage\Pdo
{
    /**
     * @var array{familyId: string}|null
     */
    private ?array $refreshTokenRotation = null;

    /**
     * @param mixed $connection
     * @param array<string, mixed> $config
     */
    public function __construct($connection, $config = [])
    {
        try {
            $config = [
                'client_table' => Setup::getTable('oauth_clients'),
                'access_token_table' => Setup::getTable('oauth_access_tokens'),
                'refresh_token_table' => Setup::getTable('oauth_refresh_tokens'),
                'code_table' => Setup::getTable('oauth_authorization_codes'),
                'user_table' => QUI::getUsers()->table(),
                'jwt_table' => Setup::getTable('oauth_jwt'),
//                'jti_table'           => Setup::getTable('oauth_jti'),
                'scope_table' => Setup::getTable('oauth_scopes'),
//                'public_key_table'    => Setup::getTable('oauth_public_keys')
            ];
        } catch (\Exception $Exception) {
            QUI\System\Log::writeException($Exception);
        }

        parent::__construct($connection, $config);
    }

    /**
     * Use a timing-safe, case-sensitive comparison for confidential clients.
     *
     * @param string $client_id
     * @param string|null $client_secret
     */
    public function checkClientCredentials($client_id, $client_secret = null): bool
    {
        $client = $this->getClientDetails($client_id);

        if (!is_array($client) || !is_string($client_secret)) {
            return false;
        }

        return hash_equals((string)$client['client_secret'], $client_secret);
    }

    /**
     * @param string $client_id
     * @return array<string, mixed>|false
     */
    public function getClientDetails($client_id): array|false
    {
        $client = parent::getClientDetails($client_id);

        if (!is_array($client) || !hash_equals((string)$client['client_id'], $client_id)) {
            return false;
        }

        return $client;
    }

    /**
     * @param string $access_token
     * @return array<string, mixed>|false
     */
    public function getAccessToken($access_token): array|false
    {
        $token = parent::getAccessToken($access_token);

        if (!is_array($token) || !hash_equals((string)$token['access_token'], $access_token)) {
            return false;
        }

        return $token;
    }

    /**
     * @param string $refresh_token
     * @return array<string, mixed>|false
     */
    public function getRefreshToken($refresh_token): array|false
    {
        $token = parent::getRefreshToken($refresh_token);

        if (!is_array($token) || !hash_equals((string)$token['refresh_token'], $refresh_token)) {
            return false;
        }

        return $token;
    }

    /**
     * Store refresh-token family metadata together with the upstream token.
     *
     * @param string $refresh_token
     * @param string $client_id
     * @param string|null $user_id
     * @param int|string $expires
     * @param string|null $scope
     */
    public function setRefreshToken(
        $refresh_token,
        $client_id,
        $user_id,
        $expires,
        $scope = null
    ): bool {
        $created = parent::setRefreshToken(
            $refresh_token,
            $client_id,
            $user_id,
            (string)$expires,
            $scope
        );

        if (!$created) {
            return false;
        }

        $familyId = $this->refreshTokenRotation['familyId']
            ?? bin2hex(random_bytes(16));

        try {
            $updated = QUI::getDataBaseConnection()->update(
                QUI\Utils\Doctrine::quoteIdentifier(
                    Setup::getTable('oauth_refresh_tokens')
                ),
                ['token_family_id' => $familyId],
                ['refresh_token' => $refresh_token]
            );

            if ($updated !== 1) {
                throw new \RuntimeException(
                    'The refresh token family could not be stored.'
                );
            }
        } catch (\Throwable $Exception) {
            parent::unsetRefreshToken($refresh_token);
            throw $Exception;
        }

        return true;
    }

    /**
     * Select a refresh token under a row lock inside the caller's transaction.
     *
     * @return array<string, mixed>|false
     */
    public function getRefreshTokenForUpdate(string $refreshToken): array|false
    {
        $QueryBuilder = QUI::getDataBaseConnection()->createQueryBuilder();
        $token = $QueryBuilder
            ->select('*')
            ->from(QUI\Utils\Doctrine::quoteIdentifier(
                Setup::getTable('oauth_refresh_tokens')
            ))
            ->where($QueryBuilder->expr()->eq(
                'refresh_token',
                ':refreshToken'
            ))
            ->setParameter('refreshToken', $refreshToken)
            ->setMaxResults(1)
            ->forUpdate()
            ->executeQuery()
            ->fetchAssociative();

        if (
            !is_array($token)
            || !hash_equals(
                (string)$token['refresh_token'],
                $refreshToken
            )
        ) {
            return false;
        }

        $expires = strtotime((string)$token['expires']);
        $token['expires'] = $expires === false ? 0 : $expires;

        return $token;
    }

    public function prepareRefreshTokenRotation(string $familyId): void
    {
        $this->refreshTokenRotation = [
            'familyId' => $familyId
        ];
    }

    public function clearRefreshTokenRotation(): void
    {
        $this->refreshTokenRotation = null;
    }

    public function ensureRefreshTokenFamilyId(string $refreshToken): string
    {
        $familyId = bin2hex(random_bytes(16));
        $QueryBuilder = QUI::getDataBaseConnection()->createQueryBuilder();
        $updated = $QueryBuilder
            ->update(QUI\Utils\Doctrine::quoteIdentifier(
                Setup::getTable('oauth_refresh_tokens')
            ))
            ->set('token_family_id', ':familyId')
            ->where($QueryBuilder->expr()->eq(
                'refresh_token',
                ':refreshToken'
            ))
            ->andWhere($QueryBuilder->expr()->isNull('token_family_id'))
            ->setParameter('familyId', $familyId)
            ->setParameter('refreshToken', $refreshToken)
            ->executeStatement();

        if ($updated !== 1) {
            $token = $this->getRefreshTokenForUpdate($refreshToken);
            $storedFamilyId = is_array($token)
                ? $token['token_family_id'] ?? null
                : null;

            if (!is_string($storedFamilyId) || $storedFamilyId === '') {
                throw new \RuntimeException(
                    'The refresh token family could not be initialized.'
                );
            }

            return $storedFamilyId;
        }

        return $familyId;
    }

    /**
     * @param array<string, mixed> $replacement
     */
    public function markRefreshTokenRotated(
        string $refreshToken,
        array $replacement
    ): void {
        $replacementRefreshToken = $replacement['refresh_token'] ?? null;
        $replacementAccessToken = $replacement['access_token'] ?? null;
        $expiresIn = $replacement['expires_in'] ?? null;

        if (
            !is_string($replacementRefreshToken)
            || $replacementRefreshToken === ''
            || !is_string($replacementAccessToken)
            || $replacementAccessToken === ''
            || !is_numeric($expiresIn)
        ) {
            throw new \RuntimeException(
                'The refresh-token replacement response is incomplete.'
            );
        }

        $now = time();
        $updated = QUI::getDataBaseConnection()->update(
            QUI\Utils\Doctrine::quoteIdentifier(
                Setup::getTable('oauth_refresh_tokens')
            ),
            [
                'replaced_by' => $replacementRefreshToken,
                'replacement_access_token' => $replacementAccessToken,
                'replacement_access_expires' => date(
                    'Y-m-d H:i:s',
                    $now + max(0, (int)$expiresIn)
                ),
                'replaced_at' => date('Y-m-d H:i:s', $now)
            ],
            ['refresh_token' => $refreshToken]
        );

        if ($updated !== 1) {
            throw new \RuntimeException(
                'The used refresh token could not be marked as rotated.'
            );
        }
    }

    public function revokeRefreshTokenFamily(
        string $familyId,
        ?string $fallbackToken = null
    ): void {
        if ($familyId === '') {
            if (is_string($fallbackToken) && $fallbackToken !== '') {
                parent::unsetRefreshToken($fallbackToken);
            }

            return;
        }

        $Connection = QUI::getDataBaseConnection();
        $refreshTokenTable = QUI\Utils\Doctrine::quoteIdentifier(
            Setup::getTable('oauth_refresh_tokens')
        );
        $accessTokenTable = QUI\Utils\Doctrine::quoteIdentifier(
            Setup::getTable('oauth_access_tokens')
        );

        $Connection->transactional(
            static function () use (
                $Connection,
                $refreshTokenTable,
                $accessTokenTable,
                $familyId
            ): void {
                $QueryBuilder = $Connection->createQueryBuilder();
                $accessTokens = $QueryBuilder
                    ->select('replacement_access_token')
                    ->from($refreshTokenTable)
                    ->where($QueryBuilder->expr()->eq(
                        'token_family_id',
                        ':familyId'
                    ))
                    ->andWhere($QueryBuilder->expr()->isNotNull(
                        'replacement_access_token'
                    ))
                    ->setParameter('familyId', $familyId)
                    ->executeQuery()
                    ->fetchFirstColumn();

                $QueryBuilder = $Connection->createQueryBuilder();
                $QueryBuilder
                    ->update($refreshTokenTable)
                    ->set('revoked_at', ':revokedAt')
                    ->where($QueryBuilder->expr()->eq(
                        'token_family_id',
                        ':familyId'
                    ))
                    ->setParameter('revokedAt', date('Y-m-d H:i:s'))
                    ->setParameter('familyId', $familyId)
                    ->executeStatement();

                foreach ($accessTokens as $accessToken) {
                    if (!is_string($accessToken) || $accessToken === '') {
                        continue;
                    }

                    $Connection->delete(
                        $accessTokenTable,
                        ['access_token' => $accessToken]
                    );
                }
            }
        );
    }

    /**
     * @param string $code
     * @return array<string, mixed>|false
     */
    public function getAuthorizationCode($code): array|false
    {
        $authorizationCode = parent::getAuthorizationCode($code);

        if (
            !is_array($authorizationCode)
            || !hash_equals((string)$authorizationCode['authorization_code'], $code)
        ) {
            return false;
        }

        return $authorizationCode;
    }

    public function setAuthorizationCodeResource(string $code, string $resource): void
    {
        QUI::getDataBaseConnection()->update(
            QUI\Utils\Doctrine::quoteIdentifier(Setup::getTable('oauth_authorization_codes')),
            ['resource' => $resource],
            ['authorization_code' => $code]
        );
    }

    public function setAccessTokenResource(string $accessToken, string $resource): void
    {
        QUI::getDataBaseConnection()->update(
            QUI\Utils\Doctrine::quoteIdentifier(Setup::getTable('oauth_access_tokens')),
            ['resource' => $resource],
            ['access_token' => $accessToken]
        );
    }

    public function setRefreshTokenResource(string $refreshToken, string $resource): void
    {
        QUI::getDataBaseConnection()->update(
            QUI\Utils\Doctrine::quoteIdentifier(Setup::getTable('oauth_refresh_tokens')),
            ['resource' => $resource],
            ['refresh_token' => $refreshToken]
        );
    }

    /**
     * @param string $username
     * @return array<string, mixed>|false
     */
    public function getUserDetails($username): bool|array
    {
        try {
            $User = QUI::getUsers()->getUserByName($username);
        } catch (QUI\Exception) {
            return false;
        }

        return array_merge([
            'user_id' => $User->getUUID()
        ], $User->getAttributes());
    }
}
