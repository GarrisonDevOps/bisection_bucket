# frozen_string_literal: true

module Types
  module PermissionTypes
    module SecretsManagement
      class ProjectSecretsManager < BasePermissionType
        graphql_name 'ProjectSecretsManagerPermissions'

        include Gitlab::Utils::StrongMemoize

        description 'Permissions the current user has on a project secrets manager.'

        authorize_granular_token parent_authorizes: :read_secrets_manager

        permission_field :read_metadata,
          description: 'Indicates the user can read secret metadata in this project secrets manager.',
          null: false

        permission_field :create_secrets,
          description: 'Indicates the user can create secrets in this project secrets manager.',
          null: false

        permission_field :update_secrets,
          description: 'Indicates the user can update secrets in this project secrets manager.',
          null: false

        permission_field :delete_secrets,
          description: 'Indicates the user can delete secrets in this project secrets manager.',
          null: false

        def effective_capabilities
          ::SecretsManagement::UserPermissions::ProjectEffectiveCapabilitiesService.new(
            secrets_manager: object,
            current_user: context[:current_user],
            resource: object.project
          ).execute
        end
        strong_memoize_attr :effective_capabilities

        def read_metadata
          effective_capabilities['read_metadata']
        end

        def create_secrets
          effective_capabilities['create']
        end

        def update_secrets
          effective_capabilities['update']
        end

        def delete_secrets
          effective_capabilities['delete']
        end
      end
    end
  end
end
