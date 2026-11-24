# frozen_string_literal: true

module Types
  module Ai
    # rubocop: disable Graphql/AuthorizeTypes -- parent authorization is enough
    class ToolRuleAccessType < Types::BaseObject
      graphql_name 'AiToolRuleAccess'
      description 'Permission modes of an AI tool rule for each surface'

      authorize_granular_token skip_reason: :parent_authorizes

      field :web_access,
        Types::Ai::ToolPermissionEnum,
        null: true,
        description: 'Permission mode for the web surface.'

      field :local_access,
        Types::Ai::ToolPermissionEnum,
        null: true,
        description: 'Permission mode for the local or IDE surface.'

      field :background_access,
        Types::Ai::BackgroundToolPermissionEnum,
        null: true,
        description: 'Permission mode for the background-flow surface.'

      # rubocop: enable Graphql/AuthorizeTypes
    end
  end
end
