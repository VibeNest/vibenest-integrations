Rails.application.routes.draw do
  root "auth#index"
  get "/auth/vibenest/login", to: "auth#login"
  get "/auth/vibenest/callback", to: "auth#callback"
  post "/auth/logout", to: "auth#logout"
  get "/api/session", to: "auth#session_state"
  get "/healthz", to: proc { [200, { "content-type" => "text/plain" }, ["Healthy"]] }
end
