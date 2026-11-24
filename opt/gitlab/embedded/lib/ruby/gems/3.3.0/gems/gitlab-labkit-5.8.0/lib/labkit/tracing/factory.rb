# frozen_string_literal: true

module Labkit
  module Tracing
    # Factory provides tools for setting up and configuring the
    # distributed tracing system within the process, given the
    # tracing connection string
    class Factory
      # When the probabilistic sampler is used, by default 0.1% of requests will be traced
      DEFAULT_PROBABILISTIC_RATE = 0.001

      # @param service_name [String] The service name for the tracer
      # @param connection_string [String] The connection string (e.g., "otlp://localhost:4318")
      # @yield [config] Optional configuration block for OpenTelemetry SDK customization (OTLP only)
      # @yieldparam config [OpenTelemetry::SDK::Configurator] The SDK configurator
      # @return [Tracer, nil] The configured tracer or nil if initialization fails
      def self.create_tracer(service_name, connection_string, &config_block)
        return unless connection_string.present?

        tracer =
          if Tracing.otlp_connection?(connection_string)
            OpenTelemetryFactory.create_tracer(service_name, connection_string, &config_block)
          elsif Tracing.opentracing_connection?(connection_string)
            warn_opentracing_block_ignored if config_block
            OpenTracingFactory.create_tracer(service_name, connection_string)
          else
            raise "Unknown protocol"
          end

        Tracing.configured_service_name = service_name

        tracer
      rescue StandardError => e
        warn "Unable to instantiate tracer: #{e}"
        nil
      end

      def self.warn_opentracing_block_ignored
        warn "Warning: Configuration block provided but ignored - " \
          "OpenTracing connection strings don't support SDK customization. " \
          "Use OTLP (otlp://) for OpenTelemetry SDK features."
      end
      private_class_method :warn_opentracing_block_ignored
    end
  end
end
