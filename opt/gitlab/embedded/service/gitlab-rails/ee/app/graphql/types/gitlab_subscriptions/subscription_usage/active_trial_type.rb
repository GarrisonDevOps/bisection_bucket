# frozen_string_literal: true

module Types
  module GitlabSubscriptions
    module SubscriptionUsage
      class ActiveTrialType < BaseObject
        graphql_name 'ActiveTrial'
        description 'Active trial information'

        authorize :read_subscription_usage

        field :start_date, GraphQL::Types::ISO8601Date,
          null: true,
          description: 'Trial start date.'

        field :end_date, GraphQL::Types::ISO8601Date,
          null: true,
          description: 'Trial end date.'
      end
    end
  end
end
