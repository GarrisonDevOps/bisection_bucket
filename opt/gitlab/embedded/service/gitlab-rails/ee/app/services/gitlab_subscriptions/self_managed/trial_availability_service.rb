# frozen_string_literal: true

module GitlabSubscriptions
  module SelfManaged
    class TrialAvailabilityService
      include ::Gitlab::Utils::Executable

      def execute
        response = ::Gitlab::SubscriptionPortal::Client.self_managed_trial_availability
        return false unless response[:success]

        data = response[:data]
        data.is_a?(Hash) && data[:available] == true
      rescue JSON::ParserError
        false
      end
    end
  end
end
