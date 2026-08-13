require "base64"
require "digest"
require "json"
require "jwt"
require "net/http"
require "openssl"
require "securerandom"
require "uri"

class VibeNestAuth
  attr_reader :issuer, :client_id, :client_secret, :redirect_uri

  def initialize(issuer:, client_id:, client_secret:, redirect_uri:, http: Net::HTTP)
    @issuer = issuer.end_with?("/") ? issuer : issuer + "/"
    @client_id = client_id
    @client_secret = client_secret.presence
    @redirect_uri = redirect_uri
    @http = http
    raise ArgumentError, "OIDC issuer and callback must use HTTPS" unless URI(issuer).scheme == "https" && URI(redirect_uri).scheme == "https"
  end

  def self.from_environment
    new(
      issuer: ENV.fetch("VIBENEST_AUTH_ISSUER"),
      client_id: ENV.fetch("VIBENEST_AUTH_CLIENT_ID"),
      client_secret: ENV["VIBENEST_AUTH_CLIENT_SECRET"],
      redirect_uri: ENV.fetch("VIBENEST_AUTH_REDIRECT_URI")
    )
  end

  def begin_flow(metadata)
    validate_metadata!(metadata)
    verifier = base64url(SecureRandom.random_bytes(64))
    pending = { "verifier" => verifier, "state" => base64url(SecureRandom.random_bytes(32)), "nonce" => base64url(SecureRandom.random_bytes(32)), "expires_at" => Time.now.to_i + 300 }
    query = URI.encode_www_form(
      client_id: client_id, redirect_uri: redirect_uri, response_type: "code",
      scope: "openid profile email", code_challenge: base64url(Digest::SHA256.digest(verifier)),
      code_challenge_method: "S256", state: pending["state"], nonce: pending["nonce"]
    )
    { url: metadata.fetch("authorization_endpoint") + "?" + query, pending: pending }
  end

  def complete(query, pending, metadata)
    validate_metadata!(metadata)
    unless pending && pending["expires_at"].to_i >= Time.now.to_i && query["code"].present? && secure_equal(pending["state"], query["state"])
      raise ArgumentError, "Invalid or expired OIDC callback"
    end
    form = { grant_type: "authorization_code", code: query.fetch("code"), client_id: client_id, redirect_uri: redirect_uri, code_verifier: pending.fetch("verifier") }
    form[:client_secret] = client_secret if client_secret
    token = post_form(metadata.fetch("token_endpoint"), form)
    jwks = get_json(metadata.fetch("jwks_uri"))
    claims, = JWT.decode(token.fetch("id_token"), nil, true,
      algorithms: %w[RS256 ES256], jwks: jwks, iss: issuer, verify_iss: true,
      aud: client_id, verify_aud: true, required_claims: %w[exp iat sub nonce])
    raise ArgumentError, "OIDC nonce mismatch" unless secure_equal(pending["nonce"], claims["nonce"])
    profile = token["access_token"] && metadata["userinfo_endpoint"] ? get_json(metadata["userinfo_endpoint"], bearer: token["access_token"]) : {}
    raise ArgumentError, "UserInfo subject mismatch" if profile["sub"] && profile["sub"] != claims["sub"]
    { "subject" => claims.fetch("sub"), "email" => profile["email"] || claims["email"] }
  end

  def discovery
    get_json(issuer + ".well-known/openid-configuration").tap { |metadata| validate_metadata!(metadata) }
  end

  def application_origin
    uri = URI(redirect_uri)
    "#{uri.scheme}://#{uri.host}#{uri.port == 443 ? '' : ":#{uri.port}"}"
  end

  private

  def validate_metadata!(metadata)
    raise ArgumentError, "OIDC discovery issuer mismatch" unless metadata["issuer"] == issuer
  end

  def get_json(url, bearer: nil)
    uri = URI(url); request = Net::HTTP::Get.new(uri); request["Authorization"] = "Bearer #{bearer}" if bearer
    response = @http.start(uri.host, uri.port, use_ssl: true, open_timeout: 5, read_timeout: 10) { |connection| connection.request(request) }
    raise "OIDC HTTP request failed" unless response.is_a?(Net::HTTPSuccess)
    JSON.parse(response.body)
  end

  def post_form(url, form)
    uri = URI(url); request = Net::HTTP::Post.new(uri); request.set_form_data(form)
    response = @http.start(uri.host, uri.port, use_ssl: true, open_timeout: 5, read_timeout: 10) { |connection| connection.request(request) }
    raise "OIDC token request failed" unless response.is_a?(Net::HTTPSuccess)
    JSON.parse(response.body)
  end

  def base64url(value) = Base64.urlsafe_encode64(value, padding: false)
  def secure_equal(left, right) = left.is_a?(String) && right.is_a?(String) && left.bytesize == right.bytesize && ActiveSupport::SecurityUtils.secure_compare(left, right)
end
