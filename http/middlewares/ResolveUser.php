<?php

namespace ReaZzon\JWTAuth\Http\Middlewares;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use PHPOpenSourceSaver\JWTAuth\Exceptions\JWTException;
use PHPOpenSourceSaver\JWTAuth\Exceptions\TokenBlacklistedException;
use PHPOpenSourceSaver\JWTAuth\Exceptions\TokenExpiredException;
use PHPOpenSourceSaver\JWTAuth\Exceptions\UserNotDefinedException;
use ReaZzon\JWTAuth\Classes\Guards\JWTGuard;

/**
 * Class ResolveUser
 * @package ReaZzon\JWTAuth\Http\Middlewares
 */
class ResolveUser
{
    /**
     * Handle an incoming request.
     *
     * @param Request  $request
     * @param \Closure $next
     *
     * @return mixed
     */
    public function handle(Request $request, \Closure $next)
    {
        try {
            /** @var JWTGuard $obJWTGuard */
            $obJWTGuard = app('JWTGuard');

            if (!$obJWTGuard->hasToken()) {
                return new JsonResponse(['message' => 'Token not provided'], 406);
            }

            $obJWTGuard->userOrFail();

            return $next($request);
        } catch (TokenExpiredException | UserNotDefinedException $e) {
            return new JsonResponse(['message' => 'Token is expired'], 406);
        } catch (TokenBlacklistedException $e) {
            return new JsonResponse(['message' => 'Token is blacklisted'], 406);
        } catch (JWTException $e) {
            return new JsonResponse(['message' => 'Token not found in request'], 406);
        }
    }
}
