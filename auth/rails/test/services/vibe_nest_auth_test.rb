require "test_helper"

class VibeNestAuthTest < ActiveSupport::TestCase
  def setup
    @auth = VibeNestAuth.new(issuer: "https://vibenest.net/", client_id: "client-reference", client_secret: nil, redirect_uri: "https://reference.example/auth/vibenest/callback")
  end

  test "authorization uses PKCE S256, state, nonce, and pinned callback" do
    flow = @auth.begin_flow("issuer" => "https://vibenest.net/", "authorization_endpoint" => "https://vibenest.net/oauth/authorize")
    query = URI.decode_www_form(URI(flow[:url]).query).to_h
    assert_equal "S256", query["code_challenge_method"]
    assert_equal flow[:pending]["state"], query["state"]
    assert_equal flow[:pending]["nonce"], query["nonce"]
    assert_equal "https://reference.example/auth/vibenest/callback", query["redirect_uri"]
  end

  test "insecure endpoints are rejected" do
    assert_raises(ArgumentError) { VibeNestAuth.new(issuer: "http://invalid/", client_id: "client", client_secret: nil, redirect_uri: "https://reference.example/callback") }
  end
end
