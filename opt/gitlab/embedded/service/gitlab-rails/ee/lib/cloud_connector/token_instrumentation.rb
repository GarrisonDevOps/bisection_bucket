# frozen_string_literal: true

module CloudConnector
  # Instruments token creation with Prometheus metrics
  #
  # @param jwk [Object] JSON Web Key for token signing
  # @param operation_type [String] Type of token operation:
  #   - 'self_signed': New instance token path (instance-wide token)
  #   - 'legacy': Legacy single-service token path (per-service tokens)
  # @param service_name [String, nil] Name of specific service (legacy path only)
  #   - nil for self_signed tokens (instance-wide tokens)
  #   - service name for legacy tokens (e.g. 'duo_chat', 'observability')
  class TokenInstrumentation
    def self.instrument(jwk:, operation_type:, service_name: nil, &block)
      new.instrument(jwk: jwk, operation_type: operation_type, service_name: service_name, &block)
    end

    def instrument(jwk:, operation_type:, service_name: nil)
      result = nil
      benchmark_result = Benchmark.measure do
        result = yield
      end

      record_creation_metrics(
        jwk: jwk,
        real_duration: benchmark_result.real,
        cpu_duration: benchmark_result.total,
        operation_type: operation_type,
        service_name: service_name
      )

      result
    end

    private

    def record_creation_metrics(jwk:, real_duration:, cpu_duration:, operation_type:, service_name:)
      labels = {
        operation_type: operation_type,
        service_name: service_name
      }

      labels_with_kid = labels.merge(kid: jwk.kid)

      token_issued_counter.increment(labels_with_kid)
      token_creation_real_duration_counter.increment(labels, real_duration)
      token_creation_cpu_duration_counter.increment(labels, cpu_duration)
    end

    def token_issued_counter
      create_counter(
        :cloud_connector_tokens_issued_total,
        'Total number of Cloud Connector tokens issued'
      )
    end

    def token_creation_real_duration_counter
      create_counter(
        :cloud_connector_token_creation_real_duration_seconds_total,
        'Total wall clock duration in seconds spent creating Cloud Connector tokens'
      )
    end

    def token_creation_cpu_duration_counter
      create_counter(
        :cloud_connector_token_creation_cpu_duration_seconds_total,
        'Total CPU duration in seconds spent creating Cloud Connector tokens'
      )
    end

    def create_counter(name, description)
      ::Gitlab::Metrics.counter(
        name,
        description,
        worker_id: ::Prometheus::PidProvider.worker_id
      )
    end
  end
end
