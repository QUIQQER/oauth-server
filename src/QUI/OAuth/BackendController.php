<?php

namespace QUI\OAuth;

use IntlDateFormatter;
use QUI;
use QUI\Interfaces\Users\User as QuiUserInterface;
use QUI\OAuth\Clients\Handler as OAuthClientsHandler;
use QUI\Utils\Security\Orthos;

class BackendController
{
    /**
     * Create a permanent access token for a specific QUIQQER user.
     *
     * @param QuiUserInterface $user
     * @param string|null $title
     * @return array{id: string, title: string, token: string, createDate: string}
     * @throws Exception
     */
    public function createPermanentAccessToken(QuiUserInterface $user, ?string $title = null): array
    {
        if (!empty($title)) {
            $title = Orthos::clear($title);
        }

        if (empty($title)) {
            $title = 'Bearer token ' . date('Y-m-d');
        } else {
            $title = mb_substr($title, 0, 255);
        }

        $numberOfOauthClientsWithPermanentAccessToken = OAuthClientsHandler::getNumberOfPermanentAccessTokens($user);
        $maxNumberOfOauthClientsWithPermanentAccessToken = OAuthClientsHandler::getMaxNumberOfPermanentAccessTokens($user);

        if (
            !is_null($maxNumberOfOauthClientsWithPermanentAccessToken)
            && $numberOfOauthClientsWithPermanentAccessToken >= $maxNumberOfOauthClientsWithPermanentAccessToken
        ) {
            throw new Exception([
                'quiqqer/oauth-server',
                'exception.backend.permanent_access_token_limit_reached',
                [
                    'maxTokens' => $maxNumberOfOauthClientsWithPermanentAccessToken
                ]
            ]);
        }

        try {
            $newClientId = OAuthClientsHandler::createOAuthClient($user, [], $title, true);
            $newClient = OAuthClientsHandler::getOAuthClient($newClientId);
        } catch (\Throwable $exception) {
            QUI\System\Log::writeException($exception);

            throw new Exception([
                'quiqqer/oauth-server',
                'exception.frontend.general_error'
            ]);
        }

        return $this->formatPermanentAccessToken($newClient);
    }

    /**
     * Return all permanent access tokens for a specific QUIQQER user.
     *
     * @param QuiUserInterface $user
     * @return array<array{id: string, title: string, token: string, createDate: string}>
     * @throws Exception
     */
    public function getPermanentAccessTokens(QuiUserInterface $user): array
    {
        try {
            $oauthClients = OAuthClientsHandler::getOAuthClientsWithPermanentAccessToken($user);
        } catch (\Throwable $exception) {
            QUI\System\Log::writeException($exception);

            throw new Exception([
                'quiqqer/oauth-server',
                'exception.frontend.general_error'
            ]);
        }

        return array_map([$this, 'formatPermanentAccessToken'], $oauthClients);
    }

    /**
     * Delete a permanent access token.
     *
     * @param string $oauthClientUuid
     * @return void
     * @throws Exception
     */
    public function deletePermanentAccessToken(string $oauthClientUuid): void
    {
        $oauthClientUuid = Orthos::clear($oauthClientUuid);

        try {
            $oauthClient = OAuthClientsHandler::getOAuthClient($oauthClientUuid);

            if (empty($oauthClient['client_secret_is_token'])) {
                throw new Exception([
                    'quiqqer/oauth-server',
                    'exception.backend.permanent_access_token_not_found'
                ]);
            }

            OAuthClientsHandler::removeOAuthClient($oauthClientUuid);
        } catch (Exception $exception) {
            QUI\System\Log::writeDebugException($exception);
            throw $exception;
        } catch (\Throwable $exception) {
            QUI\System\Log::writeException($exception);

            throw new Exception([
                'quiqqer/oauth-server',
                'exception.frontend.general_error'
            ]);
        }
    }

    /**
     * @param array{client_id?: string, name?: string, client_secret?: string, c_date?: int|string} $oauthClient
     * @return array{id: string, title: string, token: string, createDate: string}
     */
    protected function formatPermanentAccessToken(array $oauthClient): array
    {
        $localeDateFormatter = QUI::getLocale()->getDateFormatter(
            IntlDateFormatter::SHORT,
            IntlDateFormatter::SHORT
        );

        return [
            'id' => isset($oauthClient['client_id']) ? (string)$oauthClient['client_id'] : '',
            'title' => isset($oauthClient['name']) ? (string)$oauthClient['name'] : '',
            'token' => isset($oauthClient['client_secret']) ? (string)$oauthClient['client_secret'] : '',
            'createDate' => $localeDateFormatter->format((int)($oauthClient['c_date'] ?? 0))
        ];
    }
}
