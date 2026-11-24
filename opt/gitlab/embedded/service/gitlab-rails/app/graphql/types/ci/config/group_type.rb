# frozen_string_literal: true

module Types
  module Ci
    module Config
      # rubocop:disable Graphql/AuthorizeTypes -- Authorization handled in the CiLint mutation
      class GroupType < BaseObject
        graphql_name 'CiConfigGroupV2'

        authorize_granular_token parent_authorizes: :validate_ci_config

        field :jobs, [Types::Ci::Config::JobType], null: true,
          description: 'Jobs in group.'
        field :name, GraphQL::Types::String, null: true,
          description: 'Name of the job group.'
        field :size, GraphQL::Types::Int, null: true,
          description: 'Size of the job group.'
      end
      # rubocop:enable Graphql/AuthorizeTypes
    end
  end
end
