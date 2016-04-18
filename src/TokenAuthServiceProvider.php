<?php
/**
 * Copyright (c) 2016 IGET Serviços em comunicação digital LTDA - All rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 */

namespace IgetMaster\TokenAuth;

use Illuminate\Support\Facades\Auth;
use Illuminate\Support\ServiceProvider;

class TokenAuthServiceProvider extends ServiceProvider
{
    /**
     * Perform post-registration booting of services.
     *
     * @return void
     */
    public function boot()
    {
        Auth::extend('iget-token', function($app, $name, array $config) {
            $guard = new TokenGuard(
                Auth::createUserProvider($config['provider']),
                $app['request']
            );

            $app->refresh('request', $guard, 'setRequest');
            return $guard;
        });
    }
    /**
     * Register the service provider.
     *
     * @return void
     */
    public function register()
    {

    }
    /**
     * Get the services provided by the provider.
     *
     * @return array
     */
    public function provides()
    {
        return [];
    }
}