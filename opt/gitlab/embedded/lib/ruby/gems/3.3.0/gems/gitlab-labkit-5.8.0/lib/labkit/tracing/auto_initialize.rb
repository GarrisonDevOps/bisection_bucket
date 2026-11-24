# frozen_string_literal: true

require "uri"
require "active_support/core_ext/object/blank"

module Labkit
  module Tracing
    module AutoInitialize
      def self.detect_service_name(connection_string)
        return Labkit::Tracing::DEFAULT_SERVICE_NAME unless connection_string

        begin
          parsed = URI.parse(connection_string)
          options = TracingUtils.parse_query_string(parsed.query)

          return options[:service_name] if options[:service_name]

          warn "Labkit::Tracing: service_name not found in connection string, using default: '#{Labkit::Tracing::DEFAULT_SERVICE_NAME}'"
          Labkit::Tracing::DEFAULT_SERVICE_NAME
        rescue URI::InvalidURIError => e
          warn "Labkit::Tracing: Invalid connection string (#{e.message}), using default service name: '#{Labkit::Tracing::DEFAULT_SERVICE_NAME}'"
          Labkit::Tracing::DEFAULT_SERVICE_NAME
        end
      end

      def self.initialize!
        connection_string = ENV.fetch("GITLAB_TRACING", nil)
        return if connection_string.nil? || connection_string.empty?

        service_name = detect_service_name(connection_string)

        require "opentelemetry/instrumentation/concurrent_ruby"
        require "opentelemetry/instrumentation/net/http"
        require "opentelemetry/instrumentation/action_pack" if defined?(ActionPack)
        require "opentelemetry/instrumentation/action_mailer" if defined?(ActionMailer)
        require "opentelemetry/instrumentation/active_job" if defined?(ActiveJob)

        Factory.create_tracer(service_name, connection_string) do |c|
          # Enable only non-conflicting instrumentations
          # Exclude: ActiveSupport, ActiveRecord, ActionView, Redis, Rack, Sidekiq
          # (LabKit provides its own instrumentation for these via AbstractInstrumenter)

          # Core instrumentations
          c.use("OpenTelemetry::Instrumentation::ConcurrentRuby")

          # Rails components that don't conflict with LabKit
          c.use("OpenTelemetry::Instrumentation::ActionPack") if defined?(ActionPack)
          c.use("OpenTelemetry::Instrumentation::ActionMailer") if defined?(ActionMailer)
          c.use("OpenTelemetry::Instrumentation::ActiveJob") if defined?(ActiveJob)
        end

        enable_labkit_instrumentation
      rescue StandardError => e
        warn "Labkit::Tracing auto-initialization failed: #{e.message}"
      end

      def self.enable_labkit_instrumentation
        Rails::ActiveRecord::Subscriber.instrument if defined?(::ActiveRecord)
        Rails::ActionView::Subscriber.instrument if defined?(::ActionView)
        Rails::ActiveSupport::Subscriber.instrument if defined?(::ActiveSupport)
        Redis.instrument if defined?(::Redis)
        ExternalHttp.instrument
      rescue StandardError => e
        warn "Labkit::Tracing: LabKit instrumentation setup failed: #{e.message}"
      end
    end
  end
end
