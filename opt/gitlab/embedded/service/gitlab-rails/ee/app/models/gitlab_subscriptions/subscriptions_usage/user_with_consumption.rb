# frozen_string_literal: true

module GitlabSubscriptions
  module SubscriptionsUsage
    class UserWithConsumption < SimpleDelegator
      def initialize(user, consumption)
        super(user)

        @usage = UserConsumptionStatistics.new(user, consumption)
      end

      attr_reader :usage

      def entity_type
        usage.entity_type || 'user'
      end

      def declarative_policy_subject
        __getobj__
      end
    end
  end
end
