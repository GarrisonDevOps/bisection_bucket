# frozen_string_literal: true

module GitlabSubscriptions
  class TrialTypeConstraint
    def matches?(_request)
      ::Gitlab::Saas.feature_available?(:subscriptions_trials)
    end
  end
end
