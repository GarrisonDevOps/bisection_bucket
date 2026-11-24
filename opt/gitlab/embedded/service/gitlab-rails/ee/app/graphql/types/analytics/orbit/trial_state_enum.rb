# frozen_string_literal: true

module Types
  module Analytics
    module Orbit
      class TrialStateEnum < BaseEnum
        graphql_name 'OrbitTrialState'
        description 'State of the Orbit trial for a top-level group.'

        value 'ELIGIBLE', value: :eligible, description: 'Group can start a trial.',
          experiment: { milestone: '19.5' }
        value 'NOT_ELIGIBLE', value: :not_eligible, description: 'Group cannot start a trial.',
          experiment: { milestone: '19.5' }
        value 'ACTIVE', value: :active, description: 'Trial is active.',
          experiment: { milestone: '19.5' }
        value 'ENDED', value: :ended, description: 'Trial expired or used all its credits.',
          experiment: { milestone: '19.5' }
      end
    end
  end
end
