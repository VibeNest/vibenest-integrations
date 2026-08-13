require_relative "boot"
require "rails"
require "action_controller/railtie"
Bundler.require(*Rails.groups)
module VibeNestCombinedReference
  class Application < Rails::Application
    config.load_defaults 8.1
    config.eager_load = ENV.fetch("RAILS_ENV", "development") == "production"
    config.secret_key_base = ENV.fetch("SECRET_KEY_BASE")
    config.session_store :cookie_store, key: "vibenest_app_session", secure: true, httponly: true, same_site: :lax
    config.autoload_paths << Rails.root.join("../../auth/rails/app/services")
    config.autoload_paths << Rails.root.join("../../payments/rails/app/services")
  end
end
