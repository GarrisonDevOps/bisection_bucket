# frozen_string_literal: true

module Mutations
  module MergeRequests
    class DestroyRequestedChanges < BaseMutation
      graphql_name 'MergeRequestDestroyRequestedChanges'

      include Mutations::ResolvesIssuable

      authorize_granular_token permissions: :create_merge_request_review, boundary_argument: :project_path,
        boundary_type: :project

      argument :project_path, GraphQL::Types::ID,
        required: true,
        description: "Project the merge request to mutate is in."

      argument :iid, GraphQL::Types::String,
        required: true,
        description: "IID of the merge request to mutate."

      field :merge_request,
        Types::MergeRequestType,
        null: true,
        description: "Merge request after mutation."

      authorize :create_merge_request_review

      def resolve(project_path:, iid:)
        merge_request = authorized_find!(project_path: project_path, iid: iid)

        result = ::MergeRequests::DestroyRequestedChangesService.new(
          project: merge_request.project,
          current_user: current_user
        ).execute(merge_request)

        {
          merge_request: merge_request,
          errors: Array(result[:message])
        }
      end

      private

      def find_object(project_path:, iid:)
        resolve_issuable(type: :merge_request, parent_path: project_path, iid: iid)
      end
    end
  end
end
