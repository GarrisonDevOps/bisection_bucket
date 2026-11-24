# frozen_string_literal: true

module Resolvers
  module Ci
    class RunnerUsageByProjectResolver < BaseResolver
      include Gitlab::Utils::StrongMemoize
      include Gitlab::Graphql::Authorize::AuthorizeResource

      MAX_PROJECTS_LIMIT = 500
      DEFAULT_PROJECTS_LIMIT = 5

      authorize :read_runner_usage

      type [Types::Ci::RunnerUsageByProjectType], null: true
      description <<~MD
        Runner usage in minutes by project.
        Available only to administrators and users with the Maintainer role for the group (when a group is specified),
        or project (when a project is specified).
      MD

      argument :runner_type, ::Types::Ci::RunnerTypeEnum,
        required: false,
        description: 'Filter jobs by the type of runner that executed them.'

      argument :full_path, GraphQL::Types::ID,
        required: false,
        description: 'Filter jobs based on the full path of the group or project they belong to. ' \
          'For example, `gitlab-org` or `gitlab-org/gitlab`. ' \
          'Available only to administrators and users with the Maintainer role for the group ' \
          '(when a group is specified), or project (when a project is specified). ' \
          "Limited to runners from #{::Ci::Runners::GetUsageByProjectService::MAX_PROJECTS_IN_GROUP} child projects."

      argument :from_date, Types::DateType,
        required: false,
        description: 'Start of the requested date frame. Defaults to the start of the previous calendar month.'

      argument :to_date, Types::DateType,
        required: false,
        description: 'End of the requested date frame. Defaults to the end of the previous calendar month.'

      argument :projects_limit, GraphQL::Types::Int,
        required: false,
        description:
          'Maximum number of projects to return. ' \
          'Other projects will be aggregated to a `project: null` entry. ' \
          "Defaults to #{DEFAULT_PROJECTS_LIMIT} if unspecified. Maximum of #{MAX_PROJECTS_LIMIT}."

      def resolve(from_date: nil, to_date: nil, runner_type: nil, full_path: nil, projects_limit: nil)
        find_and_authorize_scope!(full_path)

        from_date ||= 1.month.ago.beginning_of_month.to_date
        to_date ||= 1.month.ago.end_of_month.to_date

        if (to_date - from_date).days > 1.year || from_date > to_date
          raise Gitlab::Graphql::Errors::ArgumentError,
            "'to_date' must be greater than 'from_date' and be within 1 year"
        end

        result = ::Ci::Runners::GetUsageByProjectService.new(
          current_user,
          runner_type: runner_type,
          scope: @group_scope || @project_scope,
          from_date: from_date,
          to_date: to_date,
          max_item_count: [MAX_PROJECTS_LIMIT, projects_limit || DEFAULT_PROJECTS_LIMIT].min
        ).execute

        raise Gitlab::Graphql::Errors::ArgumentError, result.message if result.error?

        prepare_result(result.payload)
      end

      private

      def find_and_authorize_scope!(full_path)
        return authorize! :global if full_path.nil?

        full_path = full_path.downcase # full path is always converted to lowercase for case-insensitive results
        strong_memoize_with(:find_and_authorize_scope, full_path) do
          @group_scope = Group.find_by_full_path(full_path)
          @project_scope = Project.find_by_full_path(full_path) if @group_scope.nil?

          raise_resource_not_available_error! if @group_scope.nil? && @project_scope.nil?
          authorize!(@group_scope || @project_scope)
        end
      end

      def prepare_result(payload)
        payload.map do |project_usage|
          {
            project_id: project_usage['project_id_bucket'],
            ci_minutes_used: project_usage['total_duration_in_mins'],
            ci_build_count: project_usage['count_builds']
          }
        end
      end
    end
  end
end
