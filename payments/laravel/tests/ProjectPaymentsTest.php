<?php
namespace Tests;
use App\Services\ProjectPayments;
use PHPUnit\Framework\TestCase;

final class ProjectPaymentsTest extends TestCase
{
    private string $database;
    protected function setUp(): void { $this->database=sys_get_temp_dir().'/vn-payments-'.bin2hex(random_bytes(8)).'.sqlite'; }
    protected function tearDown(): void { @unlink($this->database); }
    public function testCheckoutRejectsBrowserAuthoredBuyerAndUsesServerSubject(): void
    {
        $payments=new ProjectPayments(str_repeat('s',32),'sim_environment_reference',$this->database);
        $this->expectException(\RuntimeException::class);
        $payments->checkout('pairwise-subject',['priceKey'=>'monthly','buyerKey'=>'attacker']);
    }
    public function testExactWebhookBodyIsVerifiedAndDuplicateIsIdempotent(): void
    {
        $secret=str_repeat('s',32); $payments=new ProjectPayments($secret,'sim_environment_reference',$this->database);
        $payments->checkout('pairwise-subject',['priceKey'=>'monthly']);
        $event=['event_id'=>'evt-laravel-1','event_type'=>'transaction.completed','data'=>['status'=>'completed','customer_id'=>ProjectPayments::customerId('pairwise-subject'),'items'=>[['product_id'=>'pro','price_id'=>'monthly','quantity'=>1]],'details'=>['totals'=>['total'=>'1500','currency_code'=>'USD']],'custom_data'=>['vibenest_environment_id'=>'sim_environment_reference']]];
        $body=json_encode($event, JSON_THROW_ON_ERROR)."\n"; $now=time(); $signature='ts='.$now.';h1='.hash_hmac('sha256',$now.':'.$body,$secret);
        self::assertTrue($payments->acceptWebhook($body,$signature,$now));
        self::assertFalse($payments->acceptWebhook($body,$signature,$now));
        self::assertSame(1,$payments->entitlementQuantity('pairwise-subject'));
        $this->expectException(\RuntimeException::class); $payments->acceptWebhook($body.' ',$signature,$now);
    }
}
