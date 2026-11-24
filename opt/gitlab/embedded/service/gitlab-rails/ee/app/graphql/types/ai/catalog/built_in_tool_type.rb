# frozen_string_literal: true

module Types
  module Ai
    module Catalog
      # rubocop: disable Graphql/AuthorizeTypes -- Always public
      class BuiltInToolType < ::Types::BaseObject
        graphql_name 'AiCatalogBuiltInTool'
        description 'An AI catalog built-in tool'

        # Built-in tools are a static, public catalog of tool definitions with no owner and no
        # boundary of their own. They are reachable through an agent or agent version, through
        # `loads:` on the agent mutations, and through `Query.aiCatalogBuiltInTools`; the parents
        # and the root query field authorize the granular token themselves.
        authorize_granular_token skip_reason: :parent_authorizes

        field :description, String, null: false, description: 'Description of the built-in tool.'
        field :id, ::Types::GlobalIDType[::Ai::Catalog::BuiltInTool], null: false,
          description: 'Global ID of the built-in tool.'
        field :name, String, null: false, description: 'Name of the built-in tool.'
        field :title, String, null: false, description: 'Title of the built-in tool.'
      end
      # rubocop: enable Graphql/AuthorizeTypes
    end
  end
end
