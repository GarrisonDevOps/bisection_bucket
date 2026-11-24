# frozen_string_literal: true

module Mutations
  module Issues
    class SetEscalationPolicy < Base
      graphql_name 'IssueSetEscalationPolicy'

      authorize_granular_token permissions: :update_issue,
        boundary_argument: :project_path, boundary_type: :project

      argument :escalation_policy_id,
        ::Types::GlobalIDType[::IncidentManagement::EscalationPolicy],
        required: false,
        description: 'Global ID of the escalation policy to assign to the issue. ' \
        'Policy will be removed if absent or set to null.'

      def resolve(project_path:, iid:, escalation_policy_id: nil)
        issue = authorized_find!(project_path: project_path, iid: iid)
        project = issue.project

        escalation_policy = load_escalation_policy(escalation_policy_id)
        authorize_read_escalation_policy!(escalation_policy)

        authorize_escalation_status!(project)
        check_feature_availability!(issue)

        ::Issues::UpdateService.new(
          container: project,
          current_user: current_user,
          params: { escalation_status: { policy: escalation_policy } }
        ).execute(issue)

        {
          issue: issue,
          errors: errors_on_object(issue)
        }
      end

      private

      def authorize_read_escalation_policy!(escalation_policy)
        return unless escalation_policy.present?

        raise_resource_not_available_error! unless Ability.allowed?(
          current_user, :read_incident_management_escalation_policy, escalation_policy
        )
      end

      def load_escalation_policy(escalation_policy_id)
        return unless escalation_policy_id

        escalation_policy = Gitlab::Graphql::Lazy.force(
          GitlabSchema.find_by_gid(escalation_policy_id)
        )

        unless escalation_policy
          raise GraphQL::ExecutionError,
            "No object found for `escalationPolicyId: #{escalation_policy_id.to_s.inspect}`"
        end

        escalation_policy
      end

      def authorize_escalation_status!(project)
        return if Ability.allowed?(current_user, :update_escalation_status, project)

        raise_resource_not_available_error!
      end

      def check_feature_availability!(issue)
        return if issue.supports_escalation?

        raise_resource_not_available_error! 'Feature unavailable for provided issue'
      end
    end
  end
end
