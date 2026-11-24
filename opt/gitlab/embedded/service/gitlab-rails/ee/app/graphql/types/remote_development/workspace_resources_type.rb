# frozen_string_literal: true

# rubocop: disable Graphql/AuthorizeTypes -- because WorkspaceResources is, and should only be, accessible via WorkspacesAgentConfigType
module Types
  module RemoteDevelopment
    class WorkspaceResourcesType < ::Types::BaseObject
      graphql_name 'WorkspaceResources'
      description 'Resource specifications of the workspace container.'

      field :limits, Types::RemoteDevelopment::ResourceQuotasType,
        null: true, description: 'Limits for the requested container resources of a workspace.'
      field :requests, Types::RemoteDevelopment::ResourceQuotasType,
        null: true, description: 'Requested resources for the container of a workspace.'
    end
  end
end
# rubocop: enable Graphql/AuthorizeTypes
