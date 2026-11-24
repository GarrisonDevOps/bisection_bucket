# frozen_string_literal: true

module Mutations
  module SecretsManagement
    module ProjectSecrets
      class CreateFromLeakedToken < BaseMutation
        graphql_name 'ProjectSecretCreateFromLeakedToken'
        description 'Rotates the personal access token leaked in a specified secret detection vulnerability ' \
          'and stores the new token as a project secret. ' \
          'This revokes the leaked token and creates a token with the same lifetime. ' \
          'The new token value is not returned. Administrators can rotate tokens for any user. ' \
          'Non-administrators can only rotate their own tokens. ' \
          'Fine-grained tokens also need the `rotate_personal_access_token` permission on the user boundary.'

        include Gitlab::InternalEventsTracking
        include Helpers::ErrorMessagesHelpers
        include ::SecretsManagement::MutationErrorHandling
        include ::SecretsManagement::RequiresActiveNamespace
        include ::SecretsManagement::EnforcesWriteEntitlement

        enforces_write_entitlement_for :project_secret, find_by: :vulnerability_id

        authorize :read_vulnerability
        authorize_granular_token permissions: :create_secret,
          boundary_argument: :vulnerability_id, boundary: :project, boundary_type: :project

        argument :vulnerability_id, ::Types::GlobalIDType[::Vulnerability],
          required: true,
          description: 'Global ID of the secret detection vulnerability whose leaked token to rotate.'

        argument :name, GraphQL::Types::String,
          required: true,
          description: 'Name of the project secret.'

        argument :description, GraphQL::Types::String,
          required: false,
          description: 'Description of the project secret.'

        field :project_secret,
          Types::SecretsManagement::ProjectSecretType,
          null: true,
          description: 'Project secret created to store the rotated token.'

        def resolve(vulnerability_id:, name:, description: nil)
          vulnerability = authorized_find!(id: vulnerability_id)
          project = vulnerability.project

          raise_resource_not_available_error! unless Ability.allowed?(current_user, :create_project_secrets, project)
          raise_resource_not_available_error! if Feature.disabled?(:secrets_manager_pat_rotation, project.root_ancestor)
          raise_if_namespace_inactive!(project)
          authorize_personal_access_token_rotation!

          result = ::SecretsManagement::ProjectSecrets::CreateFromLeakedTokenService
            .new(project, current_user)
            .execute(vulnerability_id: vulnerability.id, name: name, description: description)

          if result.success?
            track_internal_event('create_ci_secret', user: current_user, namespace: project.namespace, project: project)
            { project_secret: result.payload[:secret], errors: [] }
          else
            { project_secret: nil, errors: error_messages(result, [:secret]) }
          end
        end

        private

        # The entitlement check needs the vulnerability's project; `authorized_find!` still looks up the vulnerability.
        # It runs before `authorize :read_vulnerability`, so unreadable vulnerabilities return nil and the
        # denial reason can't reveal which vulnerability IDs exist.
        def find_object(id: nil, vulnerability_id: nil)
          return super(id: id) if id

          vulnerability = Gitlab::Graphql::Lazy.force(GitlabSchema.find_by_gid(vulnerability_id))
          return unless vulnerability && Ability.allowed?(current_user, :read_vulnerability, vulnerability)

          vulnerability.project
        end

        # The directive checks create_secret on the project; rotating also needs the user-level PAT rotate permission.
        # A directive can't require a second permission on another boundary, so this check stays manual.
        def authorize_personal_access_token_rotation!
          response = ::Authz::Tokens::AuthorizeGranularScopesService.new( # rubocop:disable Gitlab/Authz/UseGranularTokenDirective -- see above
            boundaries: ::Authz::Boundary.for(:user),
            permissions: :rotate_personal_access_token,
            token: context[:access_token]
          ).execute
          return if response.success?

          ::Current.add_granular_denied_permissions(response.payload[:denied_permissions])
          raise_resource_not_available_error!(response.message)
        end
      end
    end
  end
end
