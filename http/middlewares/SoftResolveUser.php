<?php

namespace ReaZzon\JWTAuth\Http\Middlewares;

use Illuminate\Http\Request;
use ReaZzon\JWTAuth\Classes\Guards\JWTGuard;

/**
 * Class SoftResolveUser
 * @package ReaZzon\JWTAuth\Http\Middlewares
 */
class SoftResolveUser
{
    /**
     * Handle an incoming request.
     *
     * @param Request  $request
     * @param \Closure $next
     *
     * @return mixed
     */
    public function handle($obRequest, \Closure $next)
    {
        try {
            /** @var JWTGuard $obJWTGuard */
            $obJWTGuard = app('JWTGuard');
            $obJWTGuard->user();
        } catch (\Exception $ex) {
        }

        return $next($obRequest);
    }
}
