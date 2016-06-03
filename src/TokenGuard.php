<?php
/**
 * Copyright (c) 2016 IGET Serviços em comunicação digital LTDA - All rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 */

namespace IgetMaster\TokenAuth;

use Illuminate\Http\Request;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Authenticatable as AuthenticatableContract;
use Carbon\Carbon;
use Cache;


class TokenGuard implements Guard
{
    use GuardHelpers;

    /**
     * The current authorization token.
     *
     * @var string|null
     */
    public $token;

    /**
     * The request instance.
     *
     * @var \Illuminate\Http\Request
     */
    protected $request;

    /**
     * Indicates if the logout method has been called.
     *
     * @var bool
     */
    protected $loggedOut = false;

    /**
     * TokenGuard constructor.
     * @param $createUserProvider
     */
    public function __construct(UserProvider $provider, Request $request)
    {
        $this->request = $request;
        $this->provider = $provider;
    }

    /**
     * Get the currently authenticated user.
     *
     * @return \Illuminate\Contracts\Auth\Authenticatable|null
     */
    public function user() {
        if ($this->loggedOut) {
            return;
        }

        // If we've already retrieved the user for the current request we can just
        // return it back immediately. We do not want to fetch the user data on
        // every call to this method because that would be tremendously slow.
        if (! is_null($this->user)) {
            return $this->user;
        }

        $user = null;

        $this->token =  $this->getAuthorizationToken();

        if (! empty($this->token)) {
            $authorization = Cache::get('auth:' . $this->token);

            if ($authorization) {
                $user = $this->provider->retrieveById($authorization['user_id']);
            }
        }

        return $this->user = $user;
    }

    /**
     * Validate a user's credentials.
     *
     * @param  array  $credentials
     * @return bool
     */
    public function validate(array $credentials = [])
    {
        return $this->attempt($credentials, false, false);
    }

    /**
     * Attempt to authenticate a user using the given credentials.
     *
     * @param  array  $credentials
     * @param  bool   $login
     * @return bool
     */
    public function attempt(array $credentials = [], $login = true)
    {
        $this->fireAttemptEvent($credentials, $login);

        $this->lastAttempted = $user = $this->provider->retrieveByCredentials($credentials);

        // If an implementation of UserInterface was returned, we'll ask the provider
        // to validate the user against the given credentials, and if they are in
        // fact valid we'll log the users into the application and return true.
        if ($this->hasValidCredentials($user, $credentials)) {
            if ($login) {
                $this->login($user);
            }

            return true;
        }

        return false;
    }

    /**
     * Log a user into the application.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @return void
     */
    public function login(AuthenticatableContract $user)
    {
        $lifetime = config('session.lifetime');

        $user_id = $user->getAuthIdentifier();
        $expires_on = Carbon::now()->addMinutes($lifetime);
        $this->token = $this->generateAuthorizationToken();

        Cache::put('auth:' . $this->token, compact('user_id', 'expires_on'), $lifetime);

        // If we have an event dispatcher instance set we will fire an event so that
        // any listeners will hook into the authentication events and run actions
        // based on the login and logout events fired from the guard instances.
        $this->fireLoginEvent($user);

        $this->setUser($user);
    }

    /**
     * Log the user out of the application.
     *
     * @return void
     */
    public function logout()
    {
        Cache::forget('auth:' . $this->getAuthorizationToken());

        if (isset($this->events)) {
            $this->events->fire(new Events\Logout($this->user));
        }

        // Once we have fired the logout event we will clear the users out of memory
        // so they are no longer available as the user is no longer considered as
        // being signed into this application and should not be available here.
        $this->user = null;

        $this->loggedOut = true;
    }

    /**
     * Reset user to allow testing
     */
    public function resetUser()
    {
        $this->user = null;
    }

    /**
     * @return null|string
     */
    public function getToken()
    {
        return $this->token;
    }

    /**
     * Get the expiration datetime for the current authorization token
     *
     * @return \Carbon\Carbon|null
     */
    public function getExpiration()
    {
        $authentication = Cache::get('auth:' . $this->token);

        return $authentication ? $authentication['expires_on'] : null;
    }

    /**
     * Set the current request instance.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return $this
     */
    public function setRequest(Request $request)
    {
        $this->request = $request;

        return $this;
    }

    /**
     * @return string|null
     */
    protected function getAuthorizationToken()
    {
        return $this->request->header('Authorization');
    }

    /**
     * Fire the attempt event with the arguments.
     *
     * @param  array  $credentials
     * @param  bool  $login
     * @return void
     */
    protected function fireAttemptEvent(array $credentials, $login)
    {
        if (isset($this->events)) {
            $this->events->fire(new Events\Attempting(
                $credentials, false, $login
            ));
        }
    }

    /**
     * Fire the login event if the dispatcher is set.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @return void
     */
    protected function fireLoginEvent($user)
    {
        if (isset($this->events)) {
            $this->events->fire(new Events\Login($user, false));
        }
    }

    /**
     * Generate a random unique authorization token
     *
     * @param $user_id
     * @return string
     */
    protected function generateAuthorizationToken()
    {
        do {
            $token = str_random();
        } while (Cache::has("auth:${token}"));
        return $token;
    }

    /**
     * Determine if the user matches the credentials.
     *
     * @param  mixed  $user
     * @param  array  $credentials
     * @return bool
     */
    protected function hasValidCredentials($user, $credentials)
    {
        return ! is_null($user) && $this->provider->validateCredentials($user, $credentials);
    }
}
