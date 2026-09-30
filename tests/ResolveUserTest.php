<?php

namespace ReaZzon\JWTAuth\Tests;

use Illuminate\Container\Container;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use PHPOpenSourceSaver\JWTAuth\Exceptions\JWTException;
use PHPOpenSourceSaver\JWTAuth\Exceptions\TokenBlacklistedException;
use PHPOpenSourceSaver\JWTAuth\Exceptions\TokenExpiredException;
use PHPOpenSourceSaver\JWTAuth\Exceptions\UserNotDefinedException;
use PHPUnit\Framework\TestCase;
use ReaZzon\JWTAuth\Http\Middlewares\ResolveUser;

require_once __DIR__ . '/../http/middlewares/ResolveUser.php';

class ResolveUserTest extends TestCase
{
    private Container $originalContainer;

    protected function setUp(): void
    {
        parent::setUp();
        $this->originalContainer = Container::getInstance();
        Container::setInstance(new Container());
    }

    protected function tearDown(): void
    {
        Container::setInstance($this->originalContainer);
        parent::tearDown();
    }

    /** @dataProvider authenticationFailures */
    public function testAuthenticationFailuresReturnJson(
        bool $hasToken,
        ?JWTException $exception,
        string $message
    ): void {
        $guard = $this->getMockBuilder(\stdClass::class)
            ->addMethods(['hasToken', 'userOrFail'])
            ->getMock();
        $guard->expects($this->once())->method('hasToken')->willReturn($hasToken);

        if ($exception !== null) {
            $guard->expects($this->once())->method('userOrFail')->willThrowException($exception);
        } else {
            $guard->expects($this->never())->method('userOrFail');
        }

        Container::getInstance()->instance('JWTGuard', $guard);

        // No Accept header: API authentication failures must still be JSON.
        $request = Request::create('/api/v1/auth/invalidate', 'POST', ['silently' => true]);
        $response = (new ResolveUser())->handle($request, function (): void {
            $this->fail('An unauthenticated request must not reach the controller.');
        });

        $this->assertInstanceOf(JsonResponse::class, $response);
        $this->assertSame(406, $response->getStatusCode());
        $this->assertSame('application/json', $response->headers->get('Content-Type'));
        $this->assertSame(['message' => $message], json_decode($response->getContent(), true));
    }

    public static function authenticationFailures(): array
    {
        return [
            'missing token' => [false, null, 'Token not provided'],
            'expired token' => [true, new TokenExpiredException(), 'Token is expired'],
            'undefined user' => [true, new UserNotDefinedException(), 'Token is expired'],
            'blacklisted token' => [true, new TokenBlacklistedException(), 'Token is blacklisted'],
            'invalid token' => [true, new JWTException(), 'Token not found in request'],
        ];
    }

    public function testAuthenticatedRequestsReachTheController(): void
    {
        $guard = $this->getMockBuilder(\stdClass::class)
            ->addMethods(['hasToken', 'userOrFail'])
            ->getMock();
        $guard->expects($this->once())->method('hasToken')->willReturn(true);
        $guard->expects($this->once())->method('userOrFail')->willReturn(new \stdClass());
        Container::getInstance()->instance('JWTGuard', $guard);

        $request = Request::create('/api/v1/auth/invalidate', 'POST');
        $expected = new JsonResponse('token_invalidated');
        $response = (new ResolveUser())->handle($request, function (Request $actual) use ($request, $expected): JsonResponse {
            $this->assertSame($request, $actual);

            return $expected;
        });

        $this->assertSame($expected, $response);
    }
}
