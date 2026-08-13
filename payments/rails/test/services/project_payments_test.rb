require "test_helper"

class ProjectPaymentsTest < ActiveSupport::TestCase
  def setup
    @path = Rails.root.join("tmp", "payments-#{SecureRandom.hex(8)}.sqlite").to_s
    @secret = "s" * 32
    @payments = ProjectPayments.new(secret: @secret, environment_id: "sim_environment_reference", database_path: @path)
  end
  def teardown
    @payments&.close
    File.delete(@path) if @path && File.exist?(@path)
  end

  test "checkout rejects browser authored buyer ids" do
    assert_raises(ArgumentError) { @payments.checkout("pairwise-subject", { "priceKey" => "monthly", "buyerKey" => "attacker" }) }
    assert_not_includes @payments.checkout("pairwise-subject", { "priceKey" => "monthly" })[:url], "pairwise-subject"
  end

  test "webhook exact body is verified and duplicates are idempotent" do
    @payments.checkout("pairwise-subject", { "priceKey" => "monthly" })
    event = { event_id: "evt-rails-1", event_type: "transaction.completed", data: { status: "completed", customer_id: ProjectPayments.customer_id("pairwise-subject"), items: [{ product_id: "pro", price_id: "monthly", quantity: 1 }], details: { totals: { total: "1500", currency_code: "USD" } }, custom_data: { vibenest_environment_id: "sim_environment_reference" } } }
    body = JSON.generate(event) + "\n"; now = Time.now.to_i; signature = "ts=#{now};h1=#{OpenSSL::HMAC.hexdigest('SHA256', @secret, "#{now}:#{body}") }"
    assert @payments.accept_webhook(body, signature, now: now)
    assert_not @payments.accept_webhook(body, signature, now: now)
    assert_equal 1, @payments.entitlement_quantity("pairwise-subject")
    assert_raises(ArgumentError) { @payments.accept_webhook(body + " ", signature, now: now) }
  end
end
