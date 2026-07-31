<?php

namespace QUI\OAuth;

use OAuth2\GrantType\GrantTypeInterface;
use OAuth2\RequestInterface;
use OAuth2\ResponseInterface;
use OAuth2\ResponseType\AccessTokenInterface;
use QUI;

/**
 * Rotate refresh tokens as one family and make immediate retries idempotent.
 *
 * A replaced token returns the original replacement response during the
 * configured grace period. Reuse after that period revokes the complete token
 * family, including access tokens issued by its refresh operations.
 */
final class RotatingRefreshTokenGrant implements GrantTypeInterface
{
    /**
     * @var array<string, mixed>
     */
    private array $refreshToken = [];

    public function __construct(
        private readonly Storage $Storage,
        private readonly int $gracePeriod
    ) {
    }

    public function getQueryStringIdentifier(): string
    {
        return 'refresh_token';
    }

    public function validateRequest(
        RequestInterface $request,
        ResponseInterface $response
    ): ?bool {
        $refreshToken = $request->request('refresh_token');

        if (!is_string($refreshToken) || $refreshToken === '') {
            $response->setError(
                400,
                'invalid_request',
                'Missing parameter: "refresh_token" is required'
            );

            return null;
        }

        $token = $this->Storage->getRefreshToken($refreshToken);

        if (!is_array($token)) {
            $response->setError(
                400,
                'invalid_grant',
                'Invalid refresh token'
            );

            return null;
        }

        if (!empty($token['revoked_at'])) {
            $response->setError(
                400,
                'invalid_grant',
                'The refresh token family has been revoked'
            );

            return null;
        }

        if ((int)$token['expires'] > 0 && (int)$token['expires'] <= time()) {
            $response->setError(
                400,
                'invalid_grant',
                'Refresh token has expired'
            );

            return null;
        }

        if (!empty($token['replaced_by'])) {
            if (!$this->hasCompleteReplacement($token)) {
                $response->setError(
                    400,
                    'invalid_grant',
                    'The refresh token replacement is incomplete'
                );

                return null;
            }

            if (!$this->isWithinGracePeriod($token)) {
                $this->Storage->revokeRefreshTokenFamily(
                    (string)($token['token_family_id'] ?? ''),
                    $refreshToken
                );
                $response->setError(
                    400,
                    'invalid_grant',
                    'Refresh token reuse detected; the token family was revoked'
                );

                return null;
            }
        }

        $this->refreshToken = $token;

        return true;
    }

    public function getClientId(): ?string
    {
        $clientId = $this->refreshToken['client_id'] ?? null;

        return is_string($clientId) ? $clientId : null;
    }

    public function getUserId(): ?string
    {
        $userId = $this->refreshToken['user_id'] ?? null;

        return is_string($userId) ? $userId : null;
    }

    public function getScope(): ?string
    {
        $scope = $this->refreshToken['scope'] ?? null;

        return is_string($scope) ? $scope : null;
    }

    /**
     * @param string $client_id
     * @param string|null $user_id
     * @param string|null $scope
     * @return array<string, mixed>
     */
    public function createAccessToken(
        AccessTokenInterface $accessToken,
        $client_id,
        $user_id,
        $scope
    ): array {
        $usedRefreshToken = (string)$this->refreshToken['refresh_token'];

        return QUI::getDataBaseConnection()->transactional(
            function () use (
                $accessToken,
                $client_id,
                $user_id,
                $scope,
                $usedRefreshToken
            ): array {
                $current = $this->Storage->getRefreshTokenForUpdate(
                    $usedRefreshToken
                );

                if (!is_array($current) || !empty($current['revoked_at'])) {
                    throw new \RuntimeException(
                        'The refresh token family was revoked during rotation.'
                    );
                }

                if (!empty($current['replaced_by'])) {
                    if (empty($this->refreshToken['replaced_by'])) {
                        return $this->getReplacementResponse($current);
                    }

                    if (!$this->isWithinGracePeriod($current)) {
                        $this->Storage->revokeRefreshTokenFamily(
                            (string)($current['token_family_id'] ?? ''),
                            $usedRefreshToken
                        );

                        throw new \RuntimeException(
                            'Refresh token reuse was detected during rotation.'
                        );
                    }

                    return $this->getReplacementResponse($current);
                }

                $familyId = $current['token_family_id'] ?? null;

                if (!is_string($familyId) || $familyId === '') {
                    $familyId = $this->Storage->ensureRefreshTokenFamilyId(
                        $usedRefreshToken
                    );
                }

                $this->Storage->prepareRefreshTokenRotation($familyId);

                try {
                    $replacement = $accessToken->createAccessToken(
                        $client_id,
                        $user_id,
                        $scope,
                        true
                    );
                    $this->Storage->markRefreshTokenRotated(
                        $usedRefreshToken,
                        $replacement
                    );
                } finally {
                    $this->Storage->clearRefreshTokenRotation();
                }

                return $replacement;
            }
        );
    }

    /**
     * @param array<string, mixed> $token
     */
    private function isWithinGracePeriod(array $token): bool
    {
        if ($this->gracePeriod <= 0) {
            return false;
        }

        $replacedAt = strtotime((string)($token['replaced_at'] ?? ''));
        $accessExpires = strtotime(
            (string)($token['replacement_access_expires'] ?? '')
        );

        return $replacedAt !== false
            && $replacedAt + $this->gracePeriod >= time()
            && $accessExpires !== false
            && $accessExpires > time();
    }

    /**
     * @param array<string, mixed> $token
     */
    private function hasCompleteReplacement(array $token): bool
    {
        return is_string($token['replaced_by'] ?? null)
            && $token['replaced_by'] !== ''
            && is_string($token['replacement_access_token'] ?? null)
            && $token['replacement_access_token'] !== ''
            && strtotime(
                (string)($token['replacement_access_expires'] ?? '')
            ) !== false;
    }

    /**
     * @param array<string, mixed> $token
     * @return array<string, mixed>
     */
    private function getReplacementResponse(array $token): array
    {
        if (!$this->hasCompleteReplacement($token)) {
            throw new \RuntimeException(
                'The refresh token replacement response is incomplete.'
            );
        }

        $accessExpires = strtotime(
            (string)$token['replacement_access_expires']
        );

        if ($accessExpires === false) {
            throw new \RuntimeException(
                'The replacement access token expiry is invalid.'
            );
        }

        return [
            'access_token' => (string)$token['replacement_access_token'],
            'expires_in' => max(0, $accessExpires - time()),
            'token_type' => 'Bearer',
            'scope' => $token['scope'] ?? null,
            'refresh_token' => (string)$token['replaced_by']
        ];
    }
}
