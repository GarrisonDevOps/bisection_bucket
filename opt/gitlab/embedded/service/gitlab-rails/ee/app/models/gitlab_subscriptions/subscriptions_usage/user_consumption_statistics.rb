# frozen_string_literal: true

module GitlabSubscriptions
  module SubscriptionsUsage
    class UserConsumptionStatistics
      def initialize(user, consumption)
        @user = user
        @consumption = consumption
      end

      def total_credits
        consumption[:totalCredits]
      end

      def credits_used
        consumption[:creditsUsed]
      end

      def monthly_commitment_credits_used
        consumption[:monthlyCommitmentCreditsUsed]
      end

      def monthly_waiver_credits_used
        consumption[:monthlyWaiverCreditsUsed]
      end

      def overage_credits_used
        consumption[:overageCreditsUsed]
      end

      def paid_tier_trial_credits_used
        consumption[:paidTierTrialCreditsUsed]
      end

      def total_credits_used
        consumption[:totalCreditsUsed]
      end

      def non_billable_credits_used
        consumption[:nonBillableCreditsUsed]
      end

      def entity_type
        consumption[:entityType]&.downcase
      end

      def declarative_policy_subject
        user
      end

      private

      attr_reader :user, :consumption
    end
  end
end
