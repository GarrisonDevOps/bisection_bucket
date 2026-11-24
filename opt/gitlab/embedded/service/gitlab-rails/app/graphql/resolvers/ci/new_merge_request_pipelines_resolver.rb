# frozen_string_literal: true

# rubocop: disable Graphql/ResolverType -- the type is defined in ResolvesPipelines

module Resolvers
  module Ci
    # Pipelines of a merge request that is not created yet, as shown on the
    # new merge request page. The object is the source project.
    class NewMergeRequestPipelinesResolver < ::Resolvers::MergeRequestPipelinesResolver
      authorize :create_merge_request_from
      authorizes_object!
      authorize_granular_token permissions: :read_pipeline, boundary: :itself, boundary_type: :project

      # The page's badge stops at "100+" (`PIPELINE_DISPLAY_LIMIT`), so `count(limit: 100)` needs 101 rows.
      max_page_size 101

      argument :source_branch, GraphQL::Types::String,
        required: true,
        description: 'Source branch of the new merge request.'

      argument :target_branch, GraphQL::Types::String,
        required: false,
        description: 'Target branch of the new merge request. Defaults to the default branch of the target project.'

      argument :target_project_path, GraphQL::Types::ID,
        required: false,
        description: 'Full path of the target project. Defaults to the default merge request target ' \
          'of the source project.'

      def resolve(source_branch:, target_branch: nil, target_project_path: nil, **args)
        @merge_request = build_merge_request(source_branch, target_branch, target_project_path)

        super(**args)
      end

      attr_reader :merge_request

      def project
        object
      end

      private

      def build_merge_request(source_branch, target_branch, target_project_path)
        params = { source_branch: source_branch, target_branch: target_branch }.compact
        params[:target_project] = ::Project.find_by_full_path(target_project_path) if target_project_path

        # Same Gitaly N+1 as the controller: https://gitlab.com/gitlab-org/gitlab-foss/issues/58096
        Gitlab::GitalyClient.allow_n_plus_1_calls do
          ::MergeRequests::BuildService
            .new(project: object, current_user: current_user, params: params)
            .execute
        end
      end
    end
  end
end
# rubocop: enable Graphql/ResolverType
