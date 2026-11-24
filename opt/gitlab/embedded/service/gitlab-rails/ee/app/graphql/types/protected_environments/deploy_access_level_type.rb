# frozen_string_literal: true

module Types
  module ProtectedEnvironments
    # This type is authorized in the parent entity.
    # rubocop:disable Graphql/AuthorizeTypes
    class DeployAccessLevelType < AuthorizableType
      graphql_name 'ProtectedEnvironmentDeployAccessLevel'
      description 'Which group, user, or role is allowed to execute deployments to the environment.'

      authorize_granular_token permissions: :read_protected_environment,
        boundaries: [
          { boundary: :protected_environment_project, boundary_type: :project },
          { boundary: :protected_environment_group, boundary_type: :group }
        ]
    end
    # rubocop:enable Graphql/AuthorizeTypes
  end
end
