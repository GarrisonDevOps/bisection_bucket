# frozen_string_literal: true

module Types
  module SecretsManagement
    class EntitlementStateEnum < BaseEnum
      graphql_name 'SecretsManagerEntitlementState'
      description 'State of a Secrets Manager entitlement for a top-level group.'

      DESCRIPTIONS = {
        trial_eligible: 'Eligible to start a trial.',
        trial: 'Active trial.',
        paid: 'Paid subscription on a SaaS or online-cloud-licensed self-managed install.',
        offline_paid: 'Paid subscription on an offline-licensed self-managed install.',
        blocked: 'Entitlement is blocked; see blockedReason for the cause.',
        ineligible: 'Not eligible for Secrets Manager.'
      }.freeze

      ::SecretsManagement::Entitlement::STATES.each do |state|
        value state.to_s.upcase,
          value: state,
          description: DESCRIPTIONS.fetch(state, "#{state.to_s.titleize} entitlement state."),
          experiment: { milestone: '19.2' }
      end
    end
  end
end
