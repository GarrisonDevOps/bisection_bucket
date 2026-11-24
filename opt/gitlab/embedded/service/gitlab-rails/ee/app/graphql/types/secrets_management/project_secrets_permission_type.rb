# frozen_string_literal: true

module Types
  module SecretsManagement
    class ProjectSecretsPermissionType < BaseObject
      graphql_name 'ProjectSecretsPermission'
      description 'Representation of a project secrets permission.'

      include SecretsPermissionInterface

      authorize_granular_token permissions: :read_secrets_permission, boundary: :resource, boundary_type: :project

      authorize :read_project_secrets_manager

      field :project, Types::ProjectType,
        null: false,
        method: :resource,
        description: 'Project the secrets permission belongs to.'
    end
  end
end
