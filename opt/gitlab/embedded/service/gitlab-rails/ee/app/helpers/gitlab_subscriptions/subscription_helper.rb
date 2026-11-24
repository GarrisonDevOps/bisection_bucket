# frozen_string_literal: true

module GitlabSubscriptions
  module SubscriptionHelper
    def self.gitlab_com_subscription?
      ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)
    end

    def gitlab_com_subscription?
      GitlabSubscriptions::SubscriptionHelper.gitlab_com_subscription?
    end
  end
end
