class ProjectPaymentsController < ApplicationController
  skip_forgery_protection only: :webhook
  before_action :ensure_enabled!
  def prices = render(json:{provider:"simulator",prices:ProjectPayments::CATALOG})
  def checkout = render(json:service.checkout(require_subject!,request.request_parameters))
  def portal = render(json:service.portal(require_subject!))
  def webhook
    return head(:unsupported_media_type) if request.headers["Content-Encoding"].present?; service.accept_webhook(request.raw_post,request.headers["Paddle-Signature"].to_s); render json:{accepted:true},status: :accepted
  rescue ArgumentError,JSON::ParserError; head :bad_request; end
  def verifier
    return head(:not_found) unless ENV["VIBENEST_PROJECT_PAYMENTS_VERIFIER_ENABLED"]=="true"&&ActiveSupport::SecurityUtils.secure_compare(ENV.fetch("VIBENEST_PROJECT_PAYMENTS_WEBHOOK_SECRET"),request.headers["X-VibeNest-Simulator-Secret"].to_s); render json:{provider:"simulator",environmentId:ENV["VIBENEST_PROJECT_PAYMENTS_ENVIRONMENT_ID"],manifestDigest:ENV["VIBENEST_PROJECT_PAYMENTS_MANIFEST_DIGEST"],builtCommit:ENV["SOURCE_COMMIT"]}
  end
  private
  def ensure_enabled! = head(:not_found) unless ENV["VIBENEST_PROJECT_PAYMENTS_ENABLED"]=="true"&&ENV["VIBENEST_PROJECT_PAYMENTS_PROVIDER"]=="simulator"
  def require_subject! = session.dig(:user,"subject").presence||(raise ActionController::RoutingError,"Authentication required")
  def service = @service||=ProjectPayments.new(secret:ENV.fetch("VIBENEST_PROJECT_PAYMENTS_WEBHOOK_SECRET"),environment_id:ENV.fetch("VIBENEST_PROJECT_PAYMENTS_ENVIRONMENT_ID"),database_path:ENV.fetch("PROJECT_PAYMENT_FIXTURE_STORE",".data/project-payments.sqlite"))
end
