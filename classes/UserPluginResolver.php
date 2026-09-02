<?php

declare(strict_types=1);

namespace ReaZzon\JWTAuth\Classes;

use October\Rain\Auth\Manager as AuthManager;
use October\Rain\Support\Traits\Singleton;
use PHPOpenSourceSaver\JWTAuth\Contracts\JWTSubject;
use ReaZzon\JWTAuth\Classes\Contracts\Plugin;
use ReaZzon\JWTAuth\Classes\Contracts\UserPluginResolver as UserPluginResolverContract;
use System\Classes\PluginManager;

/**
 *
 */
final class UserPluginResolver implements UserPluginResolverContract
{
    use Singleton;

    private array $plugin;

    /**
     * Boot resolver
     *
     * @throws \SystemException
     *
     * @return void
     */
    public function init(): void
    {
        $plugins = $this->getSupportPlugins();

        foreach ($plugins as $plugin) {
            if (PluginManager::instance()->hasPlugin($plugin['name'])) {
                $this->plugin = $plugin;

                break;
            }
        }

        if (empty($this->plugin)) {
            throw new \SystemException('No required plugins found in system');
        }
    }

    /**
     * @return string
     */
    public function getModel(): string
    {
        return $this->plugin['model'];
    }

    public function getResolver(): Plugin
    {
        return app($this->plugin['resolver']);
    }

    /**
     * @param mixed $model
     *
     * @return JWTSubject
     */
    public function resolveModel($model): JWTSubject
    {
        return $this->getResolver()->resolve($model);
    }

    /**
     * @return AuthManager
     */
    public function getProvider(): AuthManager
    {
        return app($this->plugin['provider']);
    }

    /**
     * @return array
     */
    public function getSupportPlugins(): array
    {
        return config('reazzon.jwtauth::plugins');
    }
}
