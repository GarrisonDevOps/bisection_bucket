# frozen_string_literal: true

require "prometheus/client"

module Labkit
  module Metrics
    InvalidMetricType = Class.new(StandardError)

    # A thin wrapper around Prometheus::Client::Registry.
    # It provides a thread-safe way to register metrics with the Prometheus registry.
    class Registry
      class << self
        INIT_REGISTRY_MUTEX = Mutex.new
        REGISTER_MUTEX = Mutex.new

        # Registers a metric with the Prometheus registry in a thread-safe manner.
        # If the metric already exists, it returns the existing metric.
        # If the metric does not exist, it creates a new one.
        # Each metric-name is only registered once for a type (counter, gauge, histogram, summary),
        # even if multiple threads attempt to register the same metric simultaneously.
        #
        # @param metric_type [Symbol] The type of metric to register (:counter, :gauge, :histogram, :summary)
        # @param name [Symbol, String] The name of the metric
        # @param args [Array] Additional arguments to pass to the metric constructor
        # @return [Prometheus::Client::Metric] The registered metric
        # @raise [InvalidMetricType] If the metric_type is not supported
        #
        # @example
        #   # Register a counter
        #   counter = Registry.safe_register(:counter, :http_requests_total, 'Total HTTP requests')
        def safe_register(metric_type, name, *args)
          REGISTER_MUTEX.synchronize do
            get(name) || wrapped_registry.method(metric_type).call(name, *args)
          end
        end

        # Cleans up the Prometheus registry and resets it to a new state.
        def reset!
          INIT_REGISTRY_MUTEX.synchronize do
            Prometheus::Client.cleanup!
            Prometheus::Client.reset!
            @registry = nil
          end
        end

        # Returns the metric for the given name from the Prometheus registry.
        #
        # @param metric_name [Symbol, String] The name of the metric
        # @return [Prometheus::Client::Metric, nil] The registered metric or nil if it does not exist
        def get(metric_name)
          wrapped_registry.get(metric_name)
        end

        private

        def wrapped_registry
          @registry ||= init_registry
        end

        def init_registry
          # Prometheus::Client.registry initializes a new registry with an underlying hash
          # storing metrics and a mutex synchronizing the writes to that hash.
          # This means we need to make sure we only build one registry, for accessing from within Labkit.
          INIT_REGISTRY_MUTEX.synchronize { Prometheus::Client.registry }
        end
      end
    end
  end
end
