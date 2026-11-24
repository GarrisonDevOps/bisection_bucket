# frozen_string_literal: true

module Types
  module Ci
    # rubocop: disable Graphql/AuthorizeTypes
    module Config
      class NeedType < BaseObject
        graphql_name 'CiConfigNeed'

        authorize_granular_token parent_authorizes: :validate_ci_config

        field :name, GraphQL::Types::String, null: true,
          description: 'Name of the need.'
      end
    end
  end
end
