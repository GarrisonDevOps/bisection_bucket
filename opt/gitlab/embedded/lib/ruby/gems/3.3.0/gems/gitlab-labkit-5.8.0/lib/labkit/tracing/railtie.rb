# frozen_string_literal: true

module Labkit
  module Tracing
    class Railtie < ::Rails::Railtie
      initializer "labkit.tracing.insert_middleware", after: :load_config_initializers do |app|
        next unless Labkit::Tracing.enabled?

        # Insert after Labkit::Middleware::Rack for proper correlation ID propagation.
        app.middleware.insert_after Labkit::Middleware::Rack, Labkit::Tracing::RackMiddleware
        ::Rails.logger.info "Labkit::Tracing::RackMiddleware automatically inserted after Labkit::Middleware::Rack"
      end
    end
  end
end
