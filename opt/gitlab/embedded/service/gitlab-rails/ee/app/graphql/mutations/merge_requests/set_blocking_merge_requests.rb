# frozen_string_literal: true

module Mutations
  module MergeRequests
    class SetBlockingMergeRequests < ::Mutations::MergeRequests::Base
      graphql_name 'MergeRequestSetBlockingMergeRequests'

      authorize_granular_token permissions: :update_merge_request, boundary_argument: :project_path,
        boundary_type: :project

      argument :blocking_merge_request_references,
        [GraphQL::Types::String],
        required: true,
        description: 'Array of blocking merge request references (e.g., "!123", "project!456").'

      def resolve(project_path:, iid:, blocking_merge_request_references:)
        merge_request = authorized_find!(project_path: project_path, iid: iid)

        unless merge_request.target_project.licensed_feature_available?(:blocking_merge_requests)
          raise_resource_not_available_error! 'Blocking merge requests feature is not available'
        end

        params = {
          update_blocking_merge_request_refs: true,
          blocking_merge_request_references: blocking_merge_request_references
        }

        ::MergeRequests::UpdateService.new(
          project: merge_request.project,
          current_user: current_user,
          params: params
        ).execute(merge_request)

        {
          merge_request: merge_request,
          errors: errors_on_object(merge_request)
        }
      end
    end
  end
end
