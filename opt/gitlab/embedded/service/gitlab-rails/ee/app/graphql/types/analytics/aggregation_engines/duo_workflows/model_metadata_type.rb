# frozen_string_literal: true

module Types
  module Analytics
    module AggregationEngines
      module DuoWorkflows
        # rubocop: disable Graphql/AuthorizeTypes -- metadata for aggregated
        # rows; the mounted engine field authorizes the request.
        class ModelMetadataType < ::Types::BaseObject
          graphql_name 'DuoWorkflowsModelMetadata'
          description 'Catalog metadata for a model used by GitLab Duo Agent Platform flows'

          authorize_granular_token skip_reason: :parent_authorizes

          # Not a record, so no global ID: `hash_key` skips `BaseObject#id` and returns
          # the grouped value, which is what pairs rows across periods.
          # rubocop:disable GraphQL/UnnecessaryFieldAlias -- without it, BaseObject#id resolves a global ID
          field :id, GraphQL::Types::String, null: false, hash_key: :id,
            description: 'Stable identifier of the model across hosting providers and time periods. ' \
              'Spellings not yet mapped to a model can keep their raw value for up to 15 minutes, ' \
              'until the next alias sync and dictionary refresh.'
          # rubocop:enable GraphQL/UnnecessaryFieldAlias

          field :name, GraphQL::Types::String, null: true,
            description: 'Display name from the model catalog, or the raw value when not in the catalog. ' \
              '`null` for flows with no model attribution.'

          field :provider, GraphQL::Types::String, null: true,
            description: 'Model provider when the catalog identifies it unambiguously.'

          field :hosting, Types::Analytics::AggregationEngines::DuoWorkflows::ModelHostingEnum, null: true,
            description: 'Where the model is hosted. `null` for flows with no model attribution.'

          field :is_default, GraphQL::Types::Boolean, null: false,
            description: 'Whether the model is a configured default for GitLab Duo Agent Platform features.'
        end
        # rubocop: enable Graphql/AuthorizeTypes
      end
    end
  end
end
