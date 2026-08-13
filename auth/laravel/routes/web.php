<?php

use App\Services\VibeNestAuth;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

Route::get('/', fn () => response('<h1>VibeNest Auth reference</h1><a href="/auth/vibenest/login">Sign in with VibeNest</a>'));

Route::get('/auth/vibenest/login', function (Request $request) {
    $auth = VibeNestAuth::fromEnvironment();
    $flow = $auth->begin($auth->discovery());
    $request->session()->put('vibenest_oidc', $flow['pending']);
    return redirect()->away($flow['url'], 303);
});

Route::get('/auth/vibenest/callback', function (Request $request) {
    $auth = VibeNestAuth::fromEnvironment();
    $pending = $request->session()->pull('vibenest_oidc', []);
    $user = $auth->complete($request->query(), $pending, $auth->discovery());
    $request->session()->invalidate();
    $request->session()->regenerateToken();
    $request->session()->put('user', $user);
    return redirect()->away($auth->applicationOrigin().'/', 303);
});

Route::post('/auth/logout', function (Request $request) {
    abort_unless($request->session()->has('user.subject'), 401);
    $request->session()->invalidate();
    $request->session()->regenerateToken();
    return redirect('/', 303);
});

Route::get('/api/session', function (Request $request) {
    abort_unless($request->session()->has('user.subject'), 401);
    return response()->json(['authenticated' => true] + $request->session()->get('user'));
});
