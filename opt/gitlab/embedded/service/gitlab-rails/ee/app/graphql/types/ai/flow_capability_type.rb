# frozen_string_literal: true

module Types
  module Ai
    # rubocop: disable Graphql/AuthorizeTypes -- reachable only via the already-authorized
    # AiFlowsMetadata query (see Resolvers::Ai::FlowsMetadataResolver)
    class FlowCapabilityType < Types::BaseObject
      graphql_name 'AiFlowCapability'
      description 'A capability the instance advertises for Duo Agent Platform flows.'

      authorize_granular_token skip_reason: :parent_authorizes

      FIELD_SCOPES = [:api, :read_api, :ai_features, :ai_workflows].freeze

      def self.authorization_scopes
        FIELD_SCOPES
      end

      field :name, GraphQL::Types::String,
        scopes: FIELD_SCOPES,
        null: false,
        description: 'Name of the capability.'

      field :metadata, GraphQL::Types::JSON, # rubocop:disable Graphql/JSONType -- payload shape varies per capability
        scopes: FIELD_SCOPES,
        null: true,
        description: 'Arbitrary JSON-encoded metadata associated with the capability.'
    end
    # rubocop: enable Graphql/AuthorizeTypes
  end
end
