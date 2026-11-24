# frozen_string_literal: true

module Mutations
  module MergeRequests
    class BypassSecurityPolicy < Base
      graphql_name 'MergeRequestBypassSecurityPolicy'
      description 'Bypasses security policies for a merge request.'

      authorize_granular_token permissions: :update_merge_request, boundary_argument: :project_path,
        boundary_type: :project

      argument :security_policy_ids,
        [GraphQL::Types::ID],
        required: true,
        description: 'ID of the security policy to bypass.'

      argument :reason,
        GraphQL::Types::String,
        required: true,
        description: 'Reason for bypassing the security policy.'

      def resolve(project_path:, iid:, **args)
        merge_request = authorized_find!(project_path: project_path, iid: iid)

        result = ::Security::ScanResultPolicies::BypassMergeRequestService.new(
          merge_request: merge_request,
          current_user: current_user,
          params: args.merge(security_policy_ids: args[:security_policy_ids])
        ).execute

        {
          merge_request: result.success? ? merge_request : nil,
          errors: result.success? ? [] : [result.message]
        }
      end
    end
  end
end
