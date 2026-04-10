<?php

namespace QUI\OAuth;

use IntlDateFormatter;
use QUI;
use QUI\Interfaces\Users\User as QuiUserInterface;
use QUI\OAuth\Clients\Handler as OAuthClientsHandler;
use QUI\Permissions\Exception as QuiPermissionException;
use QUI\Utils\Security\Orthos;

class FrontendController implements FrontendControllerInterface
{
    /**
     * Creates a new OAuth client with client secret as permanent access token.
     *
     * @param ?string $title
     * @return string
     * @throws FrontendException
     */
    public function createPermanentAccessToken(QuiUserInterface $user, ?string $title = null): string
    {
        if (!empty($title)) {
            $title = Orthos::clear($title);
        }

        if (empty($title)) {
            $title = 'Bearer token ' . date('Y-m-d');
        } else {
            $title = mb_substr($title, 0, 255);
        }

        try {
            if (Permission::MANAGE_CLIENTS->has($user) === false) {
                Permission::CREATE_PERMANENT_ACCESS_TOKEN_FOR_OWN_USER->check($user);
            }

            $numberOfOauthClientsWithPermanentAccessToken = OAuthClientsHandler::getNumberOfPermanentAccessTokens(
                $user
            );
            $maxNumberOfOauthClientsWithPermanentAccessToken = OAuthClientsHandler::getMaxNumberOfPermanentAccessTokens(
                $user
            );

            if (
                !is_null($maxNumberOfOauthClientsWithPermanentAccessToken)
                && $numberOfOauthClientsWithPermanentAccessToken >= $maxNumberOfOauthClientsWithPermanentAccessToken
            ) {
                throw new FrontendException([
                    'quiqqer/oauth-server',
                    'exception.frontend.permanent_access_token_limit_reached',
                    [
                        'maxTokens' => $maxNumberOfOauthClientsWithPermanentAccessToken
                    ]
                ]);
            }

            $newClientId = OAuthClientsHandler::createOAuthClient($user, [], $title, true);
            $newClient = OAuthClientsHandler::getOAuthClient($newClientId);

            return $newClient['client_secret'];
        } catch (FrontendException $exception) {
            QUI\System\Log::writeDebugException($exception);
            throw $exception;
        } catch (QuiPermissionException $exception) {
            QUI\System\Log::writeDebugException($exception);
            throw new FrontendException([
                'quiqqer/oauth-server',
                'exception.frontend.no_permission'
            ]);
        } catch (\Throwable $Exception) {
            QUI\System\Log::writeException($Exception);
            throw new FrontendException([
                'quiqqer/oauth-server',
                'exception.frontend.general_error'
            ]);
        }
    }

    /**
     * @inheritDoc
     * @throws FrontendException
     */
    public function getPermanentAccessTokens(QuiUserInterface $user): array
    {
        try {
            $oauthClients = OAuthClientsHandler::getOAuthClientsWithPermanentAccessToken(
                $user
            );
        } catch (\Throwable $exception) {
            QUI\System\Log::writeException($exception);
            throw new FrontendException([
                'quiqqer/oauth-server',
                'exception.frontend.general_error'
            ]);
        }

        $data = [];
        $localeDateFormatter = QUI::getLocale()->getDateFormatter(
            IntlDateFormatter::SHORT,
            IntlDateFormatter::SHORT
        );

        foreach ($oauthClients as $oauthClient) {
            $title = '';
            $createDateTimestamp = 0;

            if (isset($oauthClient['name'])) {
                $title = (string)$oauthClient['name'];
            }

            if (isset($oauthClient['c_date'])) {
                $createDateTimestamp = (int)$oauthClient['c_date'];
            }

            $data[] = [
                'id' => $oauthClient['client_id'],
                'title' => $title,
                'token' => $oauthClient['client_secret'],
                'createDate' => $localeDateFormatter->format($createDateTimestamp)
            ];
        }

        return $data;
    }

    /**
     * @throws FrontendException
     */
    public function deletePermanentAccessToken(QuiUserInterface $user, string $oauthClientUuid): void
    {
        try {
            if (Permission::MANAGE_CLIENTS->has($user) === false) {
                Permission::CREATE_PERMANENT_ACCESS_TOKEN_FOR_OWN_USER->check($user);
            }

            $oauthClientUuid = Orthos::clear($oauthClientUuid);
            $oauthClient = OAuthClientsHandler::getOAuthClient($oauthClientUuid);

            if ((int)$oauthClient['user_id'] !== $user->getId()) {
                throw new FrontendException([
                    'quiqqer/oauth-server',
                    'exception.frontend.no_permission'
                ]);
            }

            OAuthClientsHandler::removeOAuthClient($oauthClientUuid);
        } catch (FrontendException $exception) {
            QUI\System\Log::writeDebugException($exception);
            throw $exception;
        } catch (QuiPermissionException $exception) {
            QUI\System\Log::writeDebugException($exception);
            throw new FrontendException([
                'quiqqer/oauth-server',
                'exception.frontend.no_permission'
            ]);
        } catch (\Throwable $exception) {
            QUI\System\Log::writeException($exception);
            throw new FrontendException([
                'quiqqer/oauth-server',
                'exception.frontend.general_error'
            ]);
        }
    }
}
