# frozen_string_literal: true

require 'opentelemetry/sdk'
require 'opentelemetry/exporter/otlp'

module Gitlab
  module Ci
    module JobTelemetry
      class Tracer
        include Singleton
        include ::Gitlab::Utils::StrongMemoize

        SERVICE_NAME = 'gitlab-ci-rails'
        TRACER_NAME = 'gitlab-ci-job-telemetry'

        # Returns an OpenTelemetry tracer backed by an isolated TracerProvider
        # that exports spans to the configured CI telemetry OTEL Collector.
        # Returns a no-op tracer when the endpoint is not configured.
        #
        # @return [OpenTelemetry::Trace::Tracer]
        def tracer
          provider.tracer(TRACER_NAME)
        end

        # The DeterministicIdGenerator installed on the tracer's provider.
        # Callers can prime a span_id via #with_span_id before calling start_span
        # to emit a span with a deterministic ID.
        def id_generator
          DeterministicIdGenerator.new
        end
        strong_memoize_attr :id_generator

        def enabled?
          endpoint.present?
        end

        # Shuts down the current provider and clears cached state.
        # The next call to #tracer will create a fresh provider and id_generator,
        # picking up any changes to the OTEL endpoint setting.
        def reset!
          provider.shutdown if provider.is_a?(::OpenTelemetry::SDK::Trace::TracerProvider)

          clear_memoization(:provider)
          clear_memoization(:id_generator)
        end

        private

        def provider
          enabled? ? new_build_provider : new_noop_provider
        end
        strong_memoize_attr :provider

        def new_build_provider
          exporter = ::OpenTelemetry::Exporter::OTLP::Exporter.new(endpoint: endpoint)
          processor = ::OpenTelemetry::SDK::Trace::Export::BatchSpanProcessor.new(exporter)

          ::OpenTelemetry::SDK::Trace::TracerProvider.new(
            resource: ::OpenTelemetry::SDK::Resources::Resource.create(
              ::OpenTelemetry::SemanticConventions::Resource::SERVICE_NAME => SERVICE_NAME
            ),
            sampler: ::OpenTelemetry::SDK::Trace::Samplers::ALWAYS_ON,
            id_generator: id_generator
          ).tap { |p| p.add_span_processor(processor) }
        rescue StandardError => e
          ::Gitlab::AppLogger.warn(
            message: 'Failed to create CI telemetry tracer',
            error_class: e.class.name,
            error_message: e.message
          )
          new_noop_provider
        end

        def new_noop_provider
          ::OpenTelemetry::Trace::TracerProvider.new
        end

        def endpoint
          ::Gitlab::CurrentSettings.ci_telemetry_otel_endpoint
        end
      end
    end
  end
end
