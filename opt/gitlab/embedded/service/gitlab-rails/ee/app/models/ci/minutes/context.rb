# frozen_string_literal: true

module Ci
  module Minutes
    class Context
      delegate :shared_runners_minutes_limit_enabled?, to: :namespace
      delegate :name, to: :namespace, prefix: true
      delegate :percent_total_minutes_remaining, :current_balance, to: :usage

      attr_reader :namespace

      def initialize(project, namespace)
        @namespace = project&.shared_runners_limit_namespace || namespace
      end

      def total
        usage.quota.total
      end

      private

      def usage
        @usage ||= ::Ci::Minutes::Usage.new(namespace)
      end
    end
  end
end
