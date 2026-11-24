# frozen_string_literal: true

module Types
  module Analytics
    module Orbit
      class TurnOnDenialReasonEnum < BaseEnum
        graphql_name 'OrbitTurnOnDenialReason'
        description 'Reason the current user cannot turn Orbit on for a group.'

        DESCRIPTIONS = {
          forbidden: 'User lacks permission to turn Orbit on for the group.',
          trial_required: 'Group must start a trial before Orbit can be turned on.',
          purchase_required: 'Group must purchase Orbit before it can be turned on, because no trial can start.',
          trial_ended: 'Trial has ended, so Orbit can no longer be turned on.',
          unavailable: 'Trial status could not be read from CustomersDot.'
        }.freeze

        ::Analytics::Orbit::Access::TURN_ON_DENIAL_REASONS.each do |reason|
          value reason.to_s.upcase,
            value: reason,
            description: DESCRIPTIONS.fetch(reason),
            experiment: { milestone: reason == :purchase_required ? '19.4' : '19.5' }
        end
      end
    end
  end
end
