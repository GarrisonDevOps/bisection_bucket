# frozen_string_literal: true

module Types
  module Analytics
    module Orbit
      class AccessStateEnum < BaseEnum
        graphql_name 'OrbitAccessState'
        description 'Access state of a group for Orbit.'

        DESCRIPTIONS = {
          not_configured: 'Orbit service is not set up on this instance.',
          unlicensed: 'Group has no Orbit access; see reason for the cause.',
          trial_eligible: 'Group can start an Orbit trial.',
          trial_active: 'Orbit trial is running.',
          trial_ended: 'Orbit trial has ended; see reason for the cause.',
          trial_not_eligible: 'Group is not eligible for an Orbit trial.',
          trial_status_unavailable: 'Trial status could not be read from CustomersDot.',
          licensed: 'Group has Orbit access; see reason for the source.'
        }.freeze

        ::Analytics::Orbit::Access::STATES.each do |state|
          value state.to_s.upcase,
            value: state,
            description: DESCRIPTIONS.fetch(state),
            experiment: { milestone: '19.5' }
        end
      end
    end
  end
end
