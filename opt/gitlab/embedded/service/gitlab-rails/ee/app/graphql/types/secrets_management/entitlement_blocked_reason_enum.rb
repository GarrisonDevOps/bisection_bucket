# frozen_string_literal: true

module Types
  module SecretsManagement
    class EntitlementBlockedReasonEnum < BaseEnum
      graphql_name 'SecretsManagerEntitlementBlockedReason'
      description 'Reason a Secrets Manager entitlement is blocked.'

      DESCRIPTIONS = {
        trial_expired: 'Trial period has ended.',
        credits_exhausted: 'No trial credits remain.',
        on_demand_disabled: 'On-demand purchasing is disabled for the namespace.',
        grace: 'Subscription has expired; access is read-only during the grace window.',
        subscription_grace_period_expired: 'Subscription is expired and the grace window has elapsed.'
      }.freeze

      ::SecretsManagement::Entitlement::BLOCKED_REASONS.each do |reason|
        value reason.to_s.upcase,
          value: reason,
          description: DESCRIPTIONS.fetch(reason, "#{reason.to_s.titleize}."),
          experiment: { milestone: '19.2' }
      end
    end
  end
end
