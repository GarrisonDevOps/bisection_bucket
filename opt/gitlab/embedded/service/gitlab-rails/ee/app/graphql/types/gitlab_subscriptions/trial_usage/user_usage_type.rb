# frozen_string_literal: true

module Types
  module GitlabSubscriptions
    module TrialUsage
      class UserUsageType < BaseObject
        graphql_name 'GitlabTrialUsageUserUsage'
        description 'Describes any credit usage for a user during a trial'

        authorize :read_user

        field :credits_used,
          type: GraphQL::Types::Float,
          null: true,
          description: 'GitLab Credits consumed by the user during a trial.'
        field :total_credits,
          type: GraphQL::Types::Float,
          null: true,
          description: 'Total GitLab Credits available to the user during a trial.'
      end
    end
  end
end
