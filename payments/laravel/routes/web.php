<?php
use App\Services\ProjectPayments;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

$payments = fn () => new ProjectPayments((string) env('VIBENEST_PROJECT_PAYMENTS_WEBHOOK_SECRET'), (string) env('VIBENEST_PROJECT_PAYMENTS_ENVIRONMENT_ID'), (string) env('PROJECT_PAYMENT_FIXTURE_STORE', '.data/project-payments.sqlite'));
$enabled = fn () => abort_unless(env('VIBENEST_PROJECT_PAYMENTS_ENABLED') === 'true' && env('VIBENEST_PROJECT_PAYMENTS_PROVIDER') === 'simulator', 404);
$subject = function (Request $request): string { $value=$request->session()->get('user.subject'); abort_unless(is_string($value) && $value !== '', 401); return $value; };

Route::get('/api/project-payments/prices', function () use ($enabled) { $enabled(); return ['provider'=>'simulator','prices'=>ProjectPayments::CATALOG]; });
Route::post('/api/project-payments/checkout', function (Request $request) use ($enabled,$subject,$payments) { $enabled(); try { return $payments()->checkout($subject($request), $request->json()->all()); } catch (RuntimeException $e) { abort(400, $e->getMessage()); } });
Route::post('/api/project-payments/portal', function (Request $request) use ($enabled,$subject,$payments) { $enabled(); return $payments()->portal($subject($request)); });
Route::post('/webhooks/project-payments', function (Request $request) use ($enabled,$payments) { $enabled(); abort_if($request->header('Content-Encoding'), 415); try { $payments()->acceptWebhook($request->getContent(), (string) $request->header('Paddle-Signature')); } catch (RuntimeException|JsonException $e) { abort(400, $e->getMessage()); } return response()->json(['accepted'=>true], 202); });
Route::get('/.well-known/vibenest/project-payments/verifier', function (Request $request) use ($enabled) { $enabled(); abort_unless(env('VIBENEST_PROJECT_PAYMENTS_VERIFIER_ENABLED') === 'true' && hash_equals((string) env('VIBENEST_PROJECT_PAYMENTS_WEBHOOK_SECRET'), (string) $request->header('X-VibeNest-Simulator-Secret')), 404); return ['provider'=>'simulator','environmentId'=>env('VIBENEST_PROJECT_PAYMENTS_ENVIRONMENT_ID'),'manifestDigest'=>env('VIBENEST_PROJECT_PAYMENTS_MANIFEST_DIGEST'),'builtCommit'=>env('SOURCE_COMMIT')]; });
