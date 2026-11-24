# frozen_string_literal: true

module Types
  module Ai
    # rubocop: disable Graphql/AuthorizeTypes -- reachable only via the already-authorized
    # top-level `aiFlowsMetadata` query field (see Resolvers::Ai::FlowsMetadataResolver)
    class FlowsMetadataType < Types::BaseObject
      graphql_name 'AiFlowsMetadata'
      description 'Metadata describing Duo Agent Platform flow capabilities available to the caller.'

      # Duo Agent Platform tokens only carry the `ai_workflows` scope, so every type and
      # field in this subtree has to accept it on top of the `api`/`read_api` default.
      FIELD_SCOPES = [:api, :read_api, :ai_features, :ai_workflows].freeze

      def self.authorization_scopes
        FIELD_SCOPES
      end

      authorize_granular_token permissions: :read_flows_metadata,
        boundaries: [
          { boundary: :group, boundary_type: :group },
          { boundary: :project, boundary_type: :project },
          { boundary: :instance, boundary_type: :instance }
        ]

      field :capabilities, [Types::Ai::FlowCapabilityType],
        scopes: FIELD_SCOPES,
        null: false,
        description: 'List of capabilities the instance advertises for Duo Agent Platform flows.'
    end
    # rubocop: enable Graphql/AuthorizeTypes
  end
end
