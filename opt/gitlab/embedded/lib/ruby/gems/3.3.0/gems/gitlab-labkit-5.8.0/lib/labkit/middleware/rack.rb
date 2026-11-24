# frozen_string_literal: true

require "action_dispatch"
require "json"

module Labkit
  module Middleware
    HEADER = "X-Gitlab-Meta"

    # This is a rack middleware to be inserted in GitLab-rails
    # It makes sure that there's always a root context containing the correlation
    # id.
    # Since this context always get's cleaned up by this middleware, we can be
    # sure that any nested contexts will also be cleaned up.
    class Rack
      def initialize(app)
        @app = app
      end

      def call(env)
        Labkit::Context.with_context(Labkit::Fields::CORRELATION_ID => correlation_id(env)) do |context|
          status, headers, response = @app.call(env)

          headers[HEADER] = context_to_json(context)

          [status, headers, response]
        end
      ensure
        reset_current_experiences
      end

      private

      def correlation_id(env)
        request(env).request_id
      end

      def request(env)
        ActionDispatch::Request.new(env)
      end

      def context_to_json(context)
        context
          .to_h
          .transform_keys { |k| k.delete_prefix("meta.") }
          .merge("version" => "1")
          .to_json
      end

      # Reset Current experiences to prevent memory leaks and cross-request contamination.
      #
      # Rails applications automatically call ActiveSupport::CurrentAttributes.reset_all
      # after each request via https://github.com/rails/rails/blob/2d4f445051b63853d48c642d0ab59ab026aa1d6a/activesupport/lib/active_support/railtie.rb,
      # but we must handle other scenarios where this middleware might be used:
      #
      # 1. Non-Rails Rack applications (Sinatra, Grape, plain Rack apps)
      # 2. Custom Rack stacks that don't include ActiveSupport::Railtie
      # 3. Test environments where Rails middleware stack might be bypassed
      # 4. Microservices or API-only applications with minimal middleware
      # 5. Background job processors that use Rack but not Rails' full stack
      #
      # By explicitly resetting here, we ensure user experiences are properly
      # cleaned up regardless of the application framework or middleware configuration.
      def reset_current_experiences
        # Only reset if the Current class is loaded to avoid unnecessary dependencies
        return unless defined?(Labkit::UserExperienceSli::Current)

        Labkit::UserExperienceSli::Current.reset
      end
    end
  end
end
