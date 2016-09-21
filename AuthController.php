<?php namespace App\Http\Controllers\Auth;

use App\User;
use Illuminate\Http\Request;
use Tymon\JWTAuth\Exception\JWTException;
use Tymon\JWTAuth\Facades\JWTAuth;
use Validator;
use App\Http\Controllers\Controller;

class AuthController extends Controller {

	/**
	 * Create a new authentication controller instance.
	 *
	 * @param  \Illuminate\Contracts\Auth\Guard  $auth
	 * @param  \Illuminate\Contracts\Auth\Registrar  $registrar
	 * @return void
	 */
	public function __construct()
	{

		$this->middleware('guest', ['except' => 'getLogout']);
	}
	public function authenticate(Request $request)
    {
        $credentials = $request->only('email','password');
        try {
            if( ! $token = JWTAuth::attempt($credentials)) {
                return $this->response->errorUnauthorized();
            }
        }catch (JWTException $ex) {
            return $this->response->errorInternal();
        }
        return $this->response->array(compact('token'))->setStatusCode(200);
    }

    /**
     * Create a new user instance after a valid registration.
     *
     * @param  array  $data
     * @return User
     */
    protected function create(array $data)
    {
        return User::create([
            'name' => $data['name'],
            'email' => $data['email'],
            'password' => bcrypt($data['password']),
        ]);
    }
    

}
