# frozen_string_literal: true

module Mutations
  module MergeRequests
    class DismissPolicyViolations < Base
      graphql_name 'DismissPolicyViolations'
      description 'Dismisses policy violations linked to a merge request'

      authorize_granular_token permissions: :update_merge_request, boundary_argument: :project_path,
        boundary_type: :project

      argument :security_policy_ids,
        [GraphQL::Types::ID],
        required: true,
        description: 'IDs of warn mode policies with violations to dismiss.'

      argument :dismissal_types,
        [Types::SecurityOrchestration::DismissalTypeEnum],
        required: true,
        description: 'Type of dismissal for the policy violations.'

      argument :comment,
        GraphQL::Types::String,
        required: true,
        description: 'Comment explaining the dismissal of the policy violations.'

      def resolve(project_path:, iid:, **args)
        merge_request = authorized_find!(project_path: project_path, iid: iid)

        result = ::Security::ScanResultPolicies::DismissPolicyViolationsService.new(
          merge_request,
          current_user: current_user,
          params: args
        ).execute

        {
          merge_request: merge_request,
          errors: result.success? ? [] : [result.message]
        }
      end
    end
  end
end
