# frozen_string_literal: true

module DuoChatPanel
  module PanelCommon
    private

    def saas?
      ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)
    end

    def subscription_expired?(record)
      saas? ? saas_subscription_expired?(record) : self_managed_subscription_expired?
    end

    def saas_subscription_expired?(record)
      namespace = record&.root_ancestor
      return false unless namespace&.gitlab_subscription

      namespace.gitlab_subscription.paid_and_expired?
    end

    def self_managed_subscription_expired?
      license = License.current
      license.present? && !license.trial? && license.expired?
    end
  end
end
