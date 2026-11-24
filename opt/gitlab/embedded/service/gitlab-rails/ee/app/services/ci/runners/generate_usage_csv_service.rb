# frozen_string_literal: true

module Ci
  module Runners
    # Generates a CSV report containing the runner usage for a given period
    #   (based on ClickHouse's ci_used_minutes_mv view)
    #
    class GenerateUsageCsvService
      include Gitlab::Utils::StrongMemoize

      MAX_PROJECT_COUNT = 1_000
      OTHER_PROJECTS_NAME = '<Other projects>'

      # @param [User] current_user The user performing the reporting
      # @param [Project, Group, nil] scope The top-level object that owns the jobs.
      #   - Project: filter jobs from the specified project. current_user needs to be at least a maintainer
      #   - Group: filter jobs from projects under the specified group. current_user needs to be at least a maintainer
      #   - nil: use all jobs. current_user must be an admin
      # @param [Symbol] runner_type The type of runners to report on, or nil to report on all types
      # @param [Date] from_date The start date of the period to examine
      # @param [Date] to_date The end date of the period to examine
      # @param [Integer] max_project_count The maximum number of projects in the report. All others will be folded
      #   into an 'Other projects' entry
      def initialize(current_user, scope:, runner_type:, from_date:, to_date:, max_project_count:)
        @current_user = current_user
        @scope = scope
        @runner_type = runner_type
        @max_project_count = [MAX_PROJECT_COUNT, max_project_count].min
        @from_date = from_date
        @to_date = to_date
      end

      def execute
        result = ::Ci::Runners::GetUsageByProjectService.new(current_user,
          scope: scope, runner_type: runner_type,
          from_date: from_date, to_date: to_date, max_item_count: max_project_count,
          additional_group_by_columns: %w[status runner_type]).execute

        return result unless result.success?

        rows = transform_rows(result.payload)
        csv_builder = CsvBuilder::SingleBatch.new(rows, header_to_value_hash)
        csv_data = csv_builder.render(ExportCsv::BaseService::TARGET_FILESIZE)
        export_status = csv_builder.status

        # rubocop: disable CodeReuse/ActiveRecord -- This is an enumerable
        # rubocop: disable Database/AvoidUsingPluckWithoutLimit -- This is an enumerable
        export_status[:projects_written] = rows.pluck('project_id_bucket').compact.sort.uniq.count
        # rubocop: enable Database/AvoidUsingPluckWithoutLimit
        # rubocop: enable CodeReuse/ActiveRecord
        export_status[:projects_expected] =
          if export_status[:truncated] || export_status[:rows_written] == 0
            max_project_count
          else
            export_status[:projects_written]
          end

        ServiceResponse.success(payload: { csv_data: csv_data, status: export_status })
      end

      private

      attr_reader :current_user, :scope, :runner_type, :from_date, :to_date, :max_project_count

      def header_to_value_hash
        {
          'Project ID' => 'project_id_bucket',
          'Project path' => 'project_path',
          'Status' => 'status',
          'Runner type' => 'runner_type',
          'Build count' => 'count_builds',
          'Total duration (minutes)' => 'total_duration_in_mins',
          'Total duration' => 'total_duration_human_readable'
        }
      end

      def transform_rows(result)
        # rubocop: disable CodeReuse/ActiveRecord -- This is a ClickHouse query
        ids = result.pluck('project_id_bucket') # rubocop: disable Database/AvoidUsingPluckWithoutLimit -- The limit is already implemented in the ClickHouse query
        # rubocop: enable CodeReuse/ActiveRecord
        return result if ids.empty?

        projects = Project.inc_routes.id_in(ids).to_h { |p| [p.id, p.full_path] }
        projects[nil] = OTHER_PROJECTS_NAME

        runner_types_by_value = Ci::Runner.runner_types.to_h.invert
        # Annotate rows with project paths, human-readable durations, etc.
        result.each do |row|
          row['project_path'] = projects[row['project_id_bucket']&.to_i]
          row['runner_type'] = runner_types_by_value[row['runner_type']&.to_i]
          row['total_duration_human_readable'] =
            ActiveSupport::Duration.build(row['total_duration_in_mins'] * 60).inspect
        end

        result
      end
    end
  end
end
