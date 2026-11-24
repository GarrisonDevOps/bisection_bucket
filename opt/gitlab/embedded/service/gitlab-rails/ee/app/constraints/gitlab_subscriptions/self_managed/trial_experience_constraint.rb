# frozen_string_literal: true

module GitlabSubscriptions
  module SelfManaged
    class TrialExperienceConstraint
      def matches?(_request)
        !::Gitlab::Dedicated.feature_available?(:skip_ultimate_trial_experience)
      end
    end
  end
end
