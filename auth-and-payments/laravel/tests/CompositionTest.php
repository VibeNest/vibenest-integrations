<?php
namespace Tests;
use App\Services\ProjectPayments; use App\Services\VibeNestAuth; use PHPUnit\Framework\TestCase;
final class CompositionTest extends TestCase
{
 public function testAuthAndPaymentsShareTheSamePairwiseSubject():void{$auth=new VibeNestAuth('https://vibenest.net/','client',null,'https://reference.example/auth/vibenest/callback');$flow=$auth->begin(['issuer'=>'https://vibenest.net/','authorization_endpoint'=>'https://vibenest.net/oauth/authorize']);self::assertArrayHasKey('nonce',$flow['pending']);$file=sys_get_temp_dir().'/vn-combined-'.bin2hex(random_bytes(8)).'.sqlite';try{$payments=new ProjectPayments(str_repeat('s',32),'sim_environment_reference',$file);$checkout=$payments->checkout('validated-pairwise-sub',['priceKey'=>'monthly']);self::assertStringNotContainsString('validated-pairwise-sub',$checkout['url']);self::assertStringContainsString(ProjectPayments::customerId('validated-pairwise-sub'),$checkout['url']);}finally{@unlink($file);}}
}
