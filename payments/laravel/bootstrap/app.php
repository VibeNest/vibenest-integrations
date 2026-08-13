<?php
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Configuration\Middleware;
return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(web: __DIR__.'/../routes/web.php', health: '/healthz')
    ->withMiddleware(fn (Middleware $middleware) => $middleware->validateCsrfTokens(except: ['webhooks/project-payments']))
    ->withExceptions(fn (Exceptions $exceptions) => null)
    ->create();
