# frozen_string_literal: true

module Mutations
  module SecurityPolicy # rubocop:disable Gitlab/BoundedContexts -- Matches CreateSecurityPolicyProject and should be fixed together
    class CreateSecurityPolicyProjectAsync < BaseMutation
      graphql_name 'SecurityPolicyProjectCreateAsync'
      description 'Creates and assigns a security policy project for the given project or group (`full_path`) async'

      include FindsProjectOrGroupForSecurityPolicies

      authorize :update_security_orchestration_policy_project

      authorize_granular_token permissions: :update_security_policy,
        boundaries: [
          { boundary_argument: :full_path, boundary_type: :project },
          { boundary_argument: :full_path, boundary_type: :group }
        ]

      argument :full_path, GraphQL::Types::String,
        required: true,
        description: 'Full path of the project or group.'

      def resolve(args)
        project_or_group = authorized_find!(**args)

        ::Security::CreateSecurityPolicyProjectWorker.perform_async(project_or_group.full_path, current_user.id) # rubocop:disable CodeReuse/Worker -- This is meant to be a background job

        {
          errors: []
        }
      end
    end
  end
end
