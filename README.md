# Laravel 5.2 - Token-based Guard

Using this guard, you can login your user like the default Laravel `session` guard, but the authorization will be
persisted using a token passed through `Authorization` HTTP Header.

## Installation

1. Require `iget-master/token-auth` on composer
2. Add the `IgetMaster\TokenAuth\TokenAuthServiceProvider::class` services provider on `app.php` configuration file.
3. Change your guard driver to `iget-token` on `auth.php`

## Usage

As on Laravel's default session guard, you must use `Auth::attempt` using the user credentials to try to login.
If successful, you can use `Auth::getToken()` to get the 16 characters random Authorization Token.

On subsequent requests, the user should pass a `Authorization` http header with this token. If the token is valid,
the user will be authenticated and you will be able to get current user using `Auth::user()`.

If you are using the Laravel's default AuthController, you must update it, since you should send to the user the
Authorization Token. Here is an example of `AuthController@getLogin` method:

```php
/**
 * @param \Request $request
 * @return \Illuminate\Http\JsonResponse
 */
public function getLogin(Request $request)
{
	$success = false;

	if (Auth::attempt($request->only(['email', 'password']))) {
		$success = true;
		$token = Auth::getToken();
		$user_id = Auth::user()->id;
	}

	return response()->json(compact('success', 'token', 'user_id'));
}
```

**Remember** to include the Request class at top of your controller class:

```php
use Illuminate\Http\Request;
```

You should change `session.lifetime` configuration to change the token's lifetime.
