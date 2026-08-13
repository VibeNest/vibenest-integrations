class AuthController < ApplicationController
  def index
    render html: '<h1>VibeNest Auth reference</h1><a href="/auth/vibenest/login">Sign in with VibeNest</a>'.html_safe
  end

  def login
    auth = VibeNestAuth.from_environment
    flow = auth.begin_flow(auth.discovery)
    session[:vibenest_oidc] = flow[:pending]
    redirect_to flow[:url], status: :see_other, allow_other_host: true
  end

  def callback
    auth = VibeNestAuth.from_environment
    pending = session.delete(:vibenest_oidc)
    user = auth.complete(params.permit(:code, :state).to_h, pending, auth.discovery)
    reset_session
    session[:user] = user
    session[:csrf] = SecureRandom.urlsafe_base64(32)
    redirect_to auth.application_origin + "/", status: :see_other, allow_other_host: true
  end

  def logout
    require_user!
    reset_session
    redirect_to root_path, status: :see_other
  end

  def session_state
    require_user!
    render json: { authenticated: true, subject: session.dig(:user, "subject"), email: session.dig(:user, "email"), csrf: session[:csrf] }
  end

  private
  def require_user! = head(:unauthorized) unless session.dig(:user, "subject").present?
end
