# frozen_string_literal: true

module Types
  module Analytics
    module Orbit
      class TrialCreditsType < BaseObject
        graphql_name 'OrbitTrialCredits'
        description 'Credits of an Orbit trial.'

        authorize :read_orbit_trial
        authorize_granular_token skip_reason: :parent_authorizes

        field :remaining, GraphQL::Types::Float,
          null: true,
          method: :credits_remaining,
          description: 'Number of trial credits remaining.',
          experiment: { milestone: '19.5' }

        field :total, GraphQL::Types::Float,
          null: true,
          method: :credits_total,
          description: 'Total number of credits granted to the trial.',
          experiment: { milestone: '19.5' }
      end
    end
  end
end
