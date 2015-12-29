<?php
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
            return new TokenGuard(
                Auth::createUserProvider($config['provider']),
                $app['request']
            );
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