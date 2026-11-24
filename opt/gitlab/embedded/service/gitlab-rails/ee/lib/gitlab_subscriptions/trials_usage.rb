# frozen_string_literal: true

module GitlabSubscriptions
  module TrialsUsage
    class Base
      include ::Gitlab::Utils::StrongMemoize

      ActiveTrial = Struct.new(:start_date, :end_date, :declarative_policy_subject)

      def initialize(
        subscription_target:,
        subscription_usage_client:,
        namespace: nil,
        organization: nil
      )
        @subscription_target = subscription_target
        @namespace = namespace
        @organization = organization
        @subscription_usage_client = subscription_usage_client
      end

      attr_reader :namespace, :organization, :subscription_usage_client, :subscription_target

      def declarative_policy_subject
        organization || namespace || :global
      end

      def active_trial
        trial_usage_response = subscription_usage_client.get_trial_usage
        return unless trial_usage_response[:success]
        return unless trial_usage_response[:trialUsage]

        ActiveTrial.new(
          start_date: trial_usage_response.dig(:trialUsage, :activeTrial, :startDate),
          end_date: trial_usage_response.dig(:trialUsage, :activeTrial, :endDate),
          declarative_policy_subject: self
        )
      end
      strong_memoize_attr :active_trial

      def trial_users_usage
        trial_usage_response = subscription_usage_client.get_trial_usage
        return unless trial_usage_response[:success]
        return unless trial_usage_response[:trialUsage]

        TrialsUsage::UserUsage.new(
          trial_usage: self
        )
      end
      strong_memoize_attr :trial_users_usage
    end
  end
end
