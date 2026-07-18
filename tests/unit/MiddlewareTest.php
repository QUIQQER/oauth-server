<?php

namespace QUITest\QUI\OAuth\Unit;

require_once __DIR__ . '/../Fixtures/AcceptingRestMiddleware.php';
require_once __DIR__ . '/../Fixtures/RejectingRestMiddleware.php';

use GuzzleHttp\Psr7\Response;
use GuzzleHttp\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use QUI\OAuth\Middleware\InvalidRequestException;
use QUI\OAuth\Middleware\RestMiddleware;

class MiddlewareTest extends TestCase
{
    public function testInvalidRequestExceptionKeepsOauthErrorInformation(): void
    {
        $Exception = new InvalidRequestException('invalid_token', 'Token rejected', 401, ['safe' => true]);

        self::assertSame('invalid_token', $Exception->getMessage());
        self::assertSame('Token rejected', $Exception->getErrorDescription());
        self::assertSame(401, $Exception->getCode());
    }

    public function testMiddlewarePassesValidRequestsToNextHandler(): void
    {
        $expected = new Response(204);
        $Handler = new class ($expected) implements RequestHandlerInterface {
            public function __construct(private ResponseInterface $Response)
            {
            }

            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                return $this->Response;
            }
        };

        $response = (new AcceptingRestMiddleware())(
            new ServerRequest('GET', '/resource'),
            $Handler
        );

        self::assertSame($expected, $response);
    }

    public function testMiddlewareReturnsSanitizedOauthErrorResponse(): void
    {
        $Handler = new class implements RequestHandlerInterface {
            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                TestCase::fail('Rejected requests must not reach the application handler.');
            }
        };

        $response = (new RejectingRestMiddleware())(
            new ServerRequest('GET', '/resource'),
            $Handler
        );
        $payload = json_decode((string)$response->getBody(), true);

        self::assertSame(403, $response->getStatusCode());
        self::assertSame('insufficient_scope', $payload['error']);
        self::assertSame('Scope denied', $payload['error_description']);
        self::assertSame(403, $payload['error_code']);
        self::assertArrayNotHasKey('access_token', $payload);
    }
}
