# frozen_string_literal: true

module Types
  module Analytics
    module Orbit
      class TrialOfferType < BaseObject
        graphql_name 'OrbitTrialOffer'
        description 'Terms of a new Orbit trial, as offered by CustomersDot.'

        authorize :read_orbit_trial
        authorize_granular_token skip_reason: :parent_authorizes

        field :duration_days, GraphQL::Types::Int,
          null: true,
          method: :offer_duration_days,
          description: 'Number of days a new trial lasts.',
          experiment: { milestone: '19.4' }

        field :initial_credits, GraphQL::Types::Float,
          null: true,
          method: :offer_credits,
          description: 'Number of free credits a new trial starts with.',
          experiment: { milestone: '19.4' }
      end
    end
  end
end
