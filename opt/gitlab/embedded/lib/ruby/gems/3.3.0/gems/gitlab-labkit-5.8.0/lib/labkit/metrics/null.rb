# frozen_string_literal: true

module Labkit
  module Metrics
    # Fakes Prometheus::Client::Metric and all derived metrics.
    # Explicitly avoiding meta-programming to make interface more obvious to interact with.
    class Null
      include Singleton

      attr_reader :name, :docstring, :base_labels

      def get(*args); end
      def set(*args); end
      def increment(*args); end
      def decrement(*args); end
      def observe(*args); end
      def values(*args); end
    end
  end
end
