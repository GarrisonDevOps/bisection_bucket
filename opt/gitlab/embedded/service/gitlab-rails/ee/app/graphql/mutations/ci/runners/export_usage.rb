# frozen_string_literal: true

module Mutations
  module Ci
    module Runners
      class ExportUsage < BaseMutation
        graphql_name 'RunnersExportUsage'

        authorize :read_runner_usage
        authorize_granular_token permissions: :read_runner_usage,
          boundaries: [
            { boundary_argument: :full_path, boundary_type: :project },
            { boundary_argument: :full_path, boundary_type: :group },
            { boundary: :instance, boundary_type: :instance }
          ]

        DEFAULT_PROJECT_COUNT = 1_000

        argument :full_path, GraphQL::Types::ID,
          required: false,
          description: 'Filter jobs by the full path of the group or project they belong to. ' \
            'For example, `gitlab-org` or `gitlab-org/gitlab`. ' \
            'Available only to administrators and users with the Maintainer role for the group ' \
            '(when a group is specified), or project (when a project is specified). ' \
            "Limited to runners from #{::Ci::Runners::GetUsageByProjectService::MAX_PROJECTS_IN_GROUP} child projects."
        argument :runner_type, ::Types::Ci::RunnerTypeEnum,
          required: false,
          description: 'Scope of the runners to include in the report.'

        argument :from_date, ::GraphQL::Types::ISO8601Date,
          required: false,
          description: 'UTC start date of the period to report on. Defaults to the start of last full month.'
        argument :to_date, ::GraphQL::Types::ISO8601Date,
          required: false,
          description: 'UTC end date of the period to report on. " \
            "Defaults to the end of the month specified by `fromDate`.'

        argument :max_project_count, ::GraphQL::Types::Int,
          required: false,
          default_value: DEFAULT_PROJECT_COUNT,
          description:
            "Maximum number of projects to return. All other runner usage will be attributed " \
            "to an `<Other projects>` entry. Defaults to #{DEFAULT_PROJECT_COUNT} projects."

        def ready?(**args)
          max_project_count = args.fetch(:max_project_count, DEFAULT_PROJECT_COUNT)

          unless max_project_count.between?(1, ::Ci::Runners::GenerateUsageCsvService::MAX_PROJECT_COUNT)
            raise Gitlab::Graphql::Errors::ArgumentError,
              "maxProjectCount must be between 1 and #{::Ci::Runners::GenerateUsageCsvService::MAX_PROJECT_COUNT}"
          end

          super
        end

        def resolve(full_path: nil, runner_type: nil, from_date: nil, to_date: nil, max_project_count: nil)
          find_and_authorize_scope!(full_path)

          from_date ||= Date.current.prev_month.beginning_of_month
          to_date ||= from_date.end_of_month

          args = {
            runner_type: ::Ci::Runner.runner_types[runner_type],
            full_path: full_path,
            from_date: from_date,
            to_date: to_date,
            max_project_count: max_project_count
          }

          ::Ci::Runners::ExportUsageCsvWorker.perform_async(current_user.id, args) # rubocop: disable CodeReuse/Worker -- this worker sends out emails

          {
            errors: []
          }
        end

        private

        def find_and_authorize_scope!(full_path)
          return authorize! :global if full_path.nil?

          scope = Group.find_by_full_path(full_path) || Project.find_by_full_path(full_path)

          raise_resource_not_available_error! if scope.nil?
          authorize! scope
        end
      end
    end
  end
end
