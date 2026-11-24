# frozen_string_literal: true

module GitlabSubscriptions
  class SubscriptionUsagePolicy < ::BasePolicy
    condition(:allowed_in_namespace) do
      can?(:read_subscription_usage, @subject.organization || @subject.namespace)
    end

    condition(:can_update_subscription_usage_cap) do
      can?(:update_subscription_usage_cap, @subject.namespace)
    end

    rule { admin | allowed_in_namespace }.policy do
      enable :read_subscription_usage
    end

    rule { admin | can_update_subscription_usage_cap }.policy do
      enable :update_subscription_usage_cap
    end
  end
end
