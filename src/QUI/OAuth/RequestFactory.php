<?php

namespace QUI\OAuth;

use OAuth2;
use Psr\Http\Message\ServerRequestInterface;

final class RequestFactory
{
    public static function fromPsr(ServerRequestInterface $Request): OAuth2\Request
    {
        $server = $Request->getServerParams();
        $server['REQUEST_METHOD'] = $Request->getMethod();

        $authorization = $Request->getHeaderLine('Authorization');
        $contentType = $Request->getHeaderLine('Content-Type');

        if ($authorization !== '') {
            $server['HTTP_AUTHORIZATION'] = $authorization;

            if (preg_match('/^Basic\s+(\S+)$/i', $authorization, $matches) === 1) {
                $credentials = base64_decode($matches[1], true);

                if (is_string($credentials) && str_contains($credentials, ':')) {
                    [$clientId, $clientSecret] = explode(':', $credentials, 2);
                    $server['PHP_AUTH_USER'] = $clientId;
                    $server['PHP_AUTH_PW'] = $clientSecret;
                }
            }
        }

        if ($contentType !== '') {
            $server['CONTENT_TYPE'] = $contentType;
        }

        $parsedBody = $Request->getParsedBody();

        return new OAuth2\Request(
            $Request->getQueryParams(),
            is_array($parsedBody) ? $parsedBody : [],
            $Request->getAttributes(),
            $Request->getCookieParams(),
            [],
            $server,
            (string)$Request->getBody()
        );
    }
}
