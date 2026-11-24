# frozen_string_literal: true

# This class provides current status of Shared Runners minutes usage for a namespace
# taking in consideration the monthly minutes allowance that Gitlab.com provides and
# any possible purchased minutes.

module Ci
  module Minutes
    class Usage
      include Gitlab::Utils::StrongMemoize

      attr_reader :namespace, :quota

      def initialize(namespace, total_minutes_used: nil)
        @namespace = namespace
        @quota = ::Ci::Minutes::Quota.new(namespace)
        @total_minutes_used = total_minutes_used unless total_minutes_used.nil?
      end

      def quota_enabled?
        quota.enabled?
      end

      def minutes_used_up?
        quota_enabled? && total_minutes_used >= quota.total
      end

      def percent_total_minutes_remaining
        return 0 unless quota_enabled?

        100 * total_minutes_remaining.to_f / quota.total.to_f
      end

      def current_balance
        quota.total - total_minutes_used
      end

      def total_minutes_used
        Ci::Minutes::NamespaceMonthlyUsage
          .all_current_usages(namespace.id)
          .pick(Arel.sql('SUM(amount_used)'))
          .to_i
      end
      strong_memoize_attr :total_minutes_used

      def reset_date
        current_usage.date
      end

      # === private to view ===
      def monthly_minutes_used_up?
        return false unless quota_enabled?

        monthly_minutes_used >= quota.monthly
      end

      def monthly_minutes_used
        total_minutes_used - purchased_minutes_used
      end

      def purchased_minutes_used_up?
        return false unless quota_enabled?

        quota.any_purchased? && purchased_minutes_used >= quota.purchased
      end

      def purchased_minutes_used
        return 0 if !quota.any_purchased? || monthly_minutes_available?

        total_minutes_used - quota.monthly
      end

      private

      def current_usage
        @current_usage ||= ::Ci::Minutes::NamespaceMonthlyUsage.find_or_create_current(namespace_id: namespace.id)
      end

      def monthly_minutes_available?
        total_minutes_used <= quota.monthly
      end

      def total_minutes_remaining
        [current_balance, 0].max
      end
    end
  end
end
