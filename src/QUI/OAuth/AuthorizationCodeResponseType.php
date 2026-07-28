<?php

namespace QUI\OAuth;

use OAuth2\ResponseType\AuthorizationCode;

final class AuthorizationCodeResponseType extends AuthorizationCode
{
    /**
     * @param array<string, mixed> $params
     * @param mixed $user_id
     * @return array{0: mixed, 1: array<string, array<string, mixed>>}
     */
    public function getAuthorizeResponse($params, $user_id = null): array
    {
        $result = parent::getAuthorizeResponse($params, $user_id);
        $code = $result[1]['query']['code'] ?? null;
        $resource = $params['resource'] ?? null;

        if (is_string($code) && is_string($resource) && $resource !== '') {
            if (!$this->storage instanceof Storage) {
                throw new \LogicException('Resource-bound authorization codes require QUI OAuth storage.');
            }

            $this->storage->setAuthorizationCodeResource($code, $resource);
        }

        return $result;
    }
}
