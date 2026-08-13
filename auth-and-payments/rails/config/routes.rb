Rails.application.routes.draw do
  root "auth#index"
  get "/auth/vibenest/login", to: "auth#login"
  get "/auth/vibenest/callback", to: "auth#callback"
  post "/auth/logout", to: "auth#logout"
  get "/api/session", to: "auth#session_state"
  get "/api/project-payments/prices", to: "project_payments#prices"
  post "/api/project-payments/checkout", to: "project_payments#checkout"
  post "/api/project-payments/portal", to: "project_payments#portal"
  post "/webhooks/project-payments", to: "project_payments#webhook"
  get "/.well-known/vibenest/project-payments/verifier", to: "project_payments#verifier"
  get "/healthz", to: proc { [200, { "content-type" => "text/plain" }, ["Healthy"]] }
end
