# frozen_string_literal: true

module Types
  module SecretsManagement
    # Every value `SecretsManagement::Entitlement#write_action_denial_reason` can produce:
    # the two non-blocked states that still deny writes (`ineligible`, `trial_required`
    # for `:trial_eligible`), plus the full set of `Entitlement::BLOCKED_REASONS`.
    class WriteActionDenialReasonEnum < BaseEnum
      graphql_name 'SecretsManagerWriteDenialReason'
      description 'Reason a Secrets Manager write was denied due to entitlement.'

      DESCRIPTIONS = {
        ineligible: 'Namespace is not eligible for Secrets Manager.',
        trial_required: 'A trial must be started before writes are allowed.',
        trial_expired: 'Trial period has ended.',
        credits_exhausted: 'No trial credits remain.',
        on_demand_disabled: 'On-demand purchasing is disabled for the namespace.',
        grace: 'Subscription has expired; access is read-only during the grace window.',
        subscription_grace_period_expired: 'Subscription is expired and the grace window has elapsed.'
      }.freeze

      VALUES = ([:ineligible, :trial_required] + ::SecretsManagement::Entitlement::BLOCKED_REASONS).freeze

      VALUES.each do |reason|
        value reason.to_s.upcase,
          value: reason,
          description: DESCRIPTIONS.fetch(reason, "#{reason.to_s.titleize}.")
      end
    end
  end
end
