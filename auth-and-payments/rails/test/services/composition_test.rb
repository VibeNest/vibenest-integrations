require "test_helper"
class CompositionTest < ActiveSupport::TestCase
  test "auth and payments share one validated pairwise subject" do
    auth=VibeNestAuth.new(issuer:"https://vibenest.net/",client_id:"client",client_secret:nil,redirect_uri:"https://reference.example/auth/vibenest/callback"); flow=auth.begin_flow("issuer"=>"https://vibenest.net/","authorization_endpoint"=>"https://vibenest.net/oauth/authorize"); assert flow[:pending]["nonce"].present?
    path=Rails.root.join("tmp","combined-#{SecureRandom.hex(8)}.sqlite").to_s
    payments=nil
    begin payments=ProjectPayments.new(secret:"s"*32,environment_id:"sim_environment_reference",database_path:path); checkout=payments.checkout("validated-pairwise-sub",{"priceKey"=>"monthly"}); assert_not_includes checkout[:url],"validated-pairwise-sub"; assert_includes checkout[:url],ProjectPayments.customer_id("validated-pairwise-sub")
    ensure payments&.close; File.delete(path) if File.exist?(path); end
  end
end
