# frozen_string_literal: true

module Types
  module Ai
    module Catalog
      module VersionInterface
        include Types::BaseInterface

        RESOLVE_TYPES = {
          ::Ai::Catalog::Item::AGENT_TYPE => ::Types::Ai::Catalog::AgentVersionType,
          ::Ai::Catalog::Item::FLOW_TYPE => ::Types::Ai::Catalog::FlowVersionType,
          ::Ai::Catalog::Item::THIRD_PARTY_FLOW_TYPE => ::Types::Ai::Catalog::ThirdPartyFlowVersionType,
          ::Ai::Catalog::Item::SKILL_TYPE => ::Types::Ai::Catalog::SkillVersionType
        }.freeze

        graphql_name 'AiCatalogItemVersion'
        description 'An AI catalog item version'

        connection_type_class ::Types::CountableConnectionType

        field :id, GraphQL::Types::ID, null: false, description: 'ID of the item version.'
        field :updated_at, Types::TimeType, null: false, description: 'Timestamp of when the item version was updated.'
        field :created_at, Types::TimeType, null: false, description: 'Timestamp of when the item version was created.'
        field :created_by, Types::UserType, null: true, description: 'User that created the item version.'
        field :released_at, Types::TimeType, null: true, method: :release_date,
          description: 'Timestamp of when the item version was released.'
        field :deprecated, GraphQL::Types::Boolean, null: false,
          description: 'Indicates the item version has been deprecated by the author.'
        field :released, GraphQL::Types::Boolean, null: false, method: :released?,
          description: 'Indicates the item version is released.'
        field :human_version_name, GraphQL::Types::String, null: true, method: :human_version,
          description: 'Human-friendly name of the item version. In the form v1.0.0-draft.'
        field :version_name, GraphQL::Types::String, null: true, method: :version,
          description: 'Version name of the item version.'
        field :item, Types::Ai::Catalog::ItemInterface, null: false, description: 'Item the version belongs to.'

        orphan_types ::Types::Ai::Catalog::AgentVersionType
        orphan_types ::Types::Ai::Catalog::FlowVersionType
        orphan_types ::Types::Ai::Catalog::ThirdPartyFlowVersionType
        orphan_types ::Types::Ai::Catalog::SkillVersionType

        def self.resolve_type(version, _context)
          item_type = version.item.item_type.to_sym

          RESOLVE_TYPES[item_type] or raise "Unknown catalog item type: #{item_type}" # rubocop:disable Style/AndOr -- Syntax error when || is used
        end

        def created_by
          return unless object.created_by_id

          Gitlab::Graphql::Loaders::BatchModelLoader.new(User, object.created_by_id).find
        end

        def item
          Gitlab::Graphql::Loaders::BatchModelLoader.new(::Ai::Catalog::Item, object.ai_catalog_item_id).find
        end
      end
    end
  end
end
