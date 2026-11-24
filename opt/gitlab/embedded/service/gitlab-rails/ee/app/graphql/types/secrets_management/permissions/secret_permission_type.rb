# frozen_string_literal: true

module Types
  module SecretsManagement
    module Permissions
      class SecretPermissionType < BaseObject
        graphql_name 'SecretPermission'
        description 'Representation of a secret permission.'

        include SecretsPermissionInterface

        authorize_granular_token permissions: :read_secrets_permission, boundary: :resource, boundary_type: :project

        authorize :read_project_secrets_manager

        field :project, Types::ProjectType,
          null: false,
          method: :resource,
          description: 'Project the secret permission belong to.'

        # Override the actions field from the interface to provide backward-compatible permissions field
        field :permissions,
          type: GraphQL::Types::String,
          null: false,
          description: "Permissions to be provided. ['create', 'update', 'read', 'delete']."

        def permissions
          # Convert actions back to old permissions format (stringified)
          actions_to_permissions_string(object.actions)
        end

        private

        # Convert actions to old permissions string format
        # WRITE action expands to both 'create' and 'update'
        def actions_to_permissions_string(actions)
          return '' if actions.blank?

          permissions = []
          actions.each do |action|
            if action == 'write'
              permissions << 'create'
              permissions << 'update'
            else
              permissions << action
            end
          end

          permissions.sort.to_s
        end
      end
    end
  end
end
