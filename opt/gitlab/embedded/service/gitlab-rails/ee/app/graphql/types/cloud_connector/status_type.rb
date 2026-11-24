# frozen_string_literal: true

# rubocop: disable Graphql/AuthorizeTypes -- this should be callable by anyone
module Types
  module CloudConnector
    class StatusType < Types::BaseObject
      graphql_name 'CloudConnectorStatus'

      field :success, GraphQL::Types::Boolean,
        null: true,
        method: :success?,
        description: 'Indicates if the setup verification was successful.'

      # rubocop: disable GraphQL/UnnecessaryFieldAlias -- to resolve via ServiceResponse hash syntax
      field :probe_results, [Types::CloudConnector::ProbeResultType],
        null: true,
        hash_key: :probe_results,
        description: 'Results of individual probes run during verification.'
      # rubocop: enable GraphQL/UnnecessaryFieldAlias
    end
  end
end
# rubocop: enable Graphql/AuthorizeTypes
