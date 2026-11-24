# frozen_string_literal: true

module Mutations
  module SecurityPolicy
    class AssignSecurityPolicyProject < BaseMutation
      graphql_name 'SecurityPolicyProjectAssign'
      description 'Assigns the specified project(`security_policy_project_id`) as security policy project ' \
        'for the given project(`full_path`). If the project already has a security policy project, ' \
        'this reassigns the project\'s security policy project with the given `security_policy_project_id`'

      include FindsProjectOrGroupForSecurityPolicies

      authorize :update_security_orchestration_policy_project

      authorize_granular_token permissions: :update_security_policy,
        boundaries: [
          { boundary_argument: :full_path, boundary_type: :project },
          { boundary_argument: :full_path, boundary_type: :group }
        ]

      argument :full_path, GraphQL::Types::String,
        required: false,
        description: 'Full path of the project or group.'

      argument :project_path, GraphQL::Types::ID,
        required: false,
        deprecated: { reason: 'Use `fullPath`', milestone: '14.10' },
        description: 'Full path of the project.'

      argument :security_policy_project_id, ::Types::GlobalIDType[::Project],
        required: true,
        description: 'ID of the security policy project.'

      def resolve(args)
        project_or_group = authorized_find!(**args)

        policy_project = find_policy_project(args[:security_policy_project_id])

        unless policy_project.present? && can_access_security_policy?(policy_project)
          raise_resource_not_available_error!
        end

        result = assign_project(project_or_group, policy_project)
        {
          errors: result.success? ? [] : [result.message]
        }
      end

      private

      def find_policy_project(id)
        ::Gitlab::Graphql::Lazy.force(GitlabSchema.object_from_id(id, expected_type: Project))
      end

      def assign_project(project_or_group, policy_project)
        ::Security::Orchestration::AssignService
          .new(
            container: project_or_group,
            current_user: current_user,
            params: { policy_project_id: policy_project.id }
          ).execute
      end

      def can_access_security_policy?(policy_project)
        Ability.allowed?(current_user, :read_security_orchestration_policy_project, policy_project)
      end
    end
  end
end
