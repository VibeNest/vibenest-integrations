require "digest"
require "json"
require "openssl"
require "sqlite3"
require "uri"

class ProjectPayments
  CATALOG = {
    "monthly" => { productKey: "pro", currency: "USD", unitAmount: 1500, type: "recurring", interval: "month" },
    "lifetime" => { productKey: "pro", currency: "USD", unitAmount: 9900, type: "one_time", interval: nil }
  }.freeze

  def initialize(secret:, environment_id:, database_path:)
    raise ArgumentError, "Webhook secret must contain at least 32 bytes" if secret.bytesize < 32
    @secret = secret; @environment_id = environment_id
    FileUtils.mkdir_p(File.dirname(database_path))
    @database = SQLite3::Database.new(database_path)
    @database.execute_batch("CREATE TABLE IF NOT EXISTS customer_subjects(customer_id TEXT PRIMARY KEY, subject TEXT NOT NULL UNIQUE); CREATE TABLE IF NOT EXISTS webhook_inbox(event_id TEXT PRIMARY KEY, body_digest TEXT NOT NULL); CREATE TABLE IF NOT EXISTS entitlements(subject TEXT NOT NULL, entitlement TEXT NOT NULL, quantity INTEGER NOT NULL, PRIMARY KEY(subject, entitlement));")
  end

  def checkout(subject, input)
    raise ArgumentError, "Use one trusted catalog priceKey" unless input.keys == ["priceKey"] && CATALOG.key?(input["priceKey"])
    customer = self.class.customer_id(subject); bind(customer, subject)
    { url: "https://simulator.invalid/checkout/#{escape(@environment_id)}/#{escape(customer)}/#{escape(input['priceKey'])}" }
  end

  def portal(subject)
    customer = self.class.customer_id(subject); bind(customer, subject)
    { url: "https://simulator.invalid/portal/#{escape(@environment_id)}/#{escape(customer)}" }
  end

  def accept_webhook(raw_body, signature, now: Time.now.to_i)
    raise ArgumentError, "Webhook exceeds the size limit" if raw_body.bytesize > 128 * 1024
    parts = signature.split(";").filter_map { |part| part.split("=", 2) if part.include?("=") }.to_h
    timestamp = Integer(parts.fetch("ts")) rescue nil
    expected = timestamp && OpenSSL::HMAC.hexdigest("SHA256", @secret, "#{timestamp}:#{raw_body}")
    unless timestamp && (now - timestamp).abs <= 300 && secure_equal(expected, parts["h1"])
      raise ArgumentError, "Invalid webhook signature"
    end
    event = JSON.parse(raw_body)
    raise ArgumentError, "Webhook environment mismatch" unless event.dig("data", "custom_data", "vibenest_environment_id") == @environment_id
    validate_event(event)
    @database.execute("BEGIN IMMEDIATE")
    begin
      @database.execute("INSERT INTO webhook_inbox(event_id, body_digest) VALUES (?, ?)", [event.fetch("event_id"), Digest::SHA256.hexdigest(raw_body)])
      if event["event_type"] == "transaction.completed"
        subject = @database.get_first_value("SELECT subject FROM customer_subjects WHERE customer_id=?", [event.dig("data", "customer_id")])
        @database.execute("INSERT INTO entitlements(subject, entitlement, quantity) VALUES (?, 'premium-access', 1) ON CONFLICT(subject, entitlement) DO UPDATE SET quantity=excluded.quantity", [subject]) if subject
      end
      @database.execute("COMMIT")
    rescue SQLite3::ConstraintException
      @database.execute("ROLLBACK")
      return false
    rescue StandardError
      @database.execute("ROLLBACK")
      raise
    end
    true
  end

  def entitlement_quantity(subject)
    @database.get_first_value("SELECT quantity FROM entitlements WHERE subject=? AND entitlement='premium-access'", [subject]).to_i
  end

  def close = @database.close

  def self.customer_id(subject) = "sim_customer_" + Digest::SHA256.hexdigest(subject)[0, 24]
  private
  def bind(customer, subject) = @database.execute("INSERT OR REPLACE INTO customer_subjects(customer_id, subject) VALUES (?, ?)", [customer, subject])
  def escape(value) = URI.encode_www_form_component(value).gsub("+", "%20")
  def secure_equal(left, right) = left.is_a?(String) && right.is_a?(String) && left.bytesize == right.bytesize && ActiveSupport::SecurityUtils.secure_compare(left, right)
  def validate_event(event)
    return unless event["event_type"] == "transaction.completed"
    data = event["data"] || {}; items = data["items"]
    raise ArgumentError, "Invalid completed transaction" unless data["status"] == "completed" && items.is_a?(Array) && items.length == 1
    item = items.first; price = CATALOG[item["price_id"]]; totals = data.dig("details", "totals") || {}
    unless price && item["product_id"] == price[:productKey] && item["quantity"] == 1 && totals["total"] == price[:unitAmount].to_s && totals["currency_code"] == price[:currency]
      raise ArgumentError, "Transaction does not match the trusted catalog"
    end
  end
end
