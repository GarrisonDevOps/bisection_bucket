# frozen_string_literal: true

require "forwardable"
require "singleton"
require 'concurrent-ruby'
require "prometheus/client"
require "labkit/metrics/registry"
require "labkit/metrics/null"

module Labkit
  module Metrics
    InvalidLabelSet = Class.new(RuntimeError)

    # A thin wrapper around Prometheus::Client from the prometheus-client-mmap gem
    # https://gitlab.com/gitlab-org/ruby/gems/prometheus-client-mmap
    class Client
      include Singleton
      extend Forwardable

      def_delegators :wrapped_client, :configure, :reinitialize_on_pid_change, :configuration

      def initialize
        @enabled = Concurrent::AtomicBoolean.new(true)
      end

      def wrapped_client
        @client ||= ::Prometheus::Client
      end

      def disable!
        @enabled.make_false
      end

      def enable!
        @enabled.make_true
      end

      def enabled?
        @enabled.true? && metrics_folder_present?
      end

      def safe_provide_metric(metric_type, name, *args)
        return Null.instance unless enabled?

        Registry.safe_register(metric_type, name, *args)
      end

      def metrics_folder_present?
        dir = configuration.multiprocess_files_dir
        dir && Dir.exist?(dir) && File.writable?(dir)
      end

      def counter(name, docstring, base_labels = {})
        safe_provide_metric(:counter, name, docstring, base_labels)
      end

      def summary(name, docstring, base_labels = {})
        safe_provide_metric(:summary, name, docstring, base_labels)
      end

      def histogram(
        name, docstring, base_labels = {},
        buckets = Prometheus::Client::Histogram::DEFAULT_BUCKETS)
        safe_provide_metric(:histogram, name, docstring, base_labels, buckets)
      end

      def gauge(name, docstring, base_labels = {}, multiprocess_mode = :all)
        safe_provide_metric(:gauge, name, docstring, base_labels, multiprocess_mode)
      end

      def reset!
        Registry.reset!
      end

      def get(metric_name)
        Registry.get(metric_name)
      end

      class << self
        extend Forwardable

        def_delegators :instance,
          :enable!, :disable!, :counter, :gauge, :histogram, :summary, :reset!, :enabled?,
          :configure, :reinitialize_on_pid_change, :configuration, :get

        private :instance
      end
    end
  end
end
