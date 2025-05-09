<?php

namespace ReaZzon\JWTAuth\Http\Middlewares;

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
                abort('406', 'Token not provided');
            }

            $obJWTGuard->userOrFail();

            return $next($request);
        } catch (TokenExpiredException | UserNotDefinedException $e) {
            abort(406, 'Token is expired');
        } catch (TokenBlacklistedException $e) {
            abort(406, 'Token is blacklisted');
        } catch (JWTException $e) {
            abort(406, 'Token not found in request');
        }
    }
}
