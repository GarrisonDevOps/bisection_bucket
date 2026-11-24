# frozen_string_literal: true

module Mutations
  module MergeRequests
    class ResyncSecurityPolicies < BaseMutation
      graphql_name 'MergeRequestResyncSecurityPolicies'
      description 'Triggers a re-evaluation of the security approval policies applicable to the merge request.'

      include Mutations::ResolvesIssuable

      authorize_granular_token permissions: :update_merge_request, boundary_argument: :project_path,
        boundary_type: :project

      argument :project_path, GraphQL::Types::ID,
        required: true,
        description: 'Project the merge request belongs to.'

      argument :iid, GraphQL::Types::String,
        required: true,
        description: 'IID of the merge request to re-evaluate.'

      field :merge_request,
        Types::MergeRequestType,
        null: true,
        description: 'Merge request after the re-evaluation was scheduled.'

      authorize :force_evaluate_merge_request_security_policy

      def resolve(project_path:, iid:)
        merge_request = authorized_find!(project_path: project_path, iid: iid)

        if rate_limit_throttled?(merge_request)
          return {
            merge_request: merge_request,
            errors: ['This merge request was re-evaluated recently. Please try again in a minute.']
          }
        end

        merge_request.schedule_policy_synchronization

        {
          merge_request: merge_request,
          errors: []
        }
      end

      private

      def rate_limit_throttled?(merge_request)
        Gitlab::ApplicationRateLimiter.throttled?(:merge_request_resync_security_policies,
          scope: { merge_request: merge_request })
      end

      def find_object(project_path:, iid:)
        resolve_issuable(type: :merge_request, parent_path: project_path, iid: iid)
      end
    end
  end
end
