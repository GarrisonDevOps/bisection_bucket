# frozen_string_literal: true

module Ci
  module Runners
    # Sends a CSV report containing the runner usage for a given period
    #   (based on ClickHouse's ci_used_minutes_mv view)
    #
    class SendUsageCsvService
      include Gitlab::Utils::StrongMemoize

      # @param [User] current_user The user performing the reporting
      # @param [String, nil] full_path The path to the top-level object that owns the jobs. It can be a path to a
      #   project, a group, or nil (in which case all jobs are considered).
      # @param [Symbol] runner_type The type of runners to report on, or nil to report on all types
      # @param [Date] from_date The start date of the period to examine
      # @param [Date] to_date The end date of the period to examine
      # @param [Integer] max_project_count The maximum number of projects in the report. All others will be folded
      #   into an 'Other projects' entry
      def initialize(current_user:, full_path:, runner_type:, from_date:, to_date:, max_project_count:)
        @current_user = current_user
        @full_path = full_path
        @runner_type = runner_type
        @from_date = from_date
        @to_date = to_date
        @max_project_count = max_project_count
      end

      def execute
        Gitlab::InternalEvents.track_event('export_runner_usage_by_project_as_csv', **internal_event_args)

        result = process_csv
        return result if result.error?

        send_email(result)
        log_audit_event(message: 'Sent email with runner usage CSV')

        ServiceResponse.success(payload: result.payload.slice(:status))
      end

      private

      def process_csv
        GenerateUsageCsvService.new(
          @current_user,
          scope: scope,
          runner_type: @runner_type,
          from_date: @from_date,
          to_date: @to_date,
          max_project_count: @max_project_count
        ).execute
      end

      def scope
        ::Group.find_by_full_path(@full_path) || ::Project.find_by_full_path(@full_path) if @full_path
      end
      strong_memoize_attr :scope

      def send_email(result)
        Notify.runner_usage_by_project_csv_email(
          user: @current_user, scope: scope, from_date: @from_date, to_date: @to_date,
          csv_data: result.payload[:csv_data], export_status: result.payload[:status]
        ).deliver_now
      end

      def internal_event_args
        args = { user: @current_user, additional_properties: { property: @runner_type&.to_s } }

        case scope
        when ::Group
          args[:namespace] = scope
          args[:additional_properties][:label] = 'group'
        when ::Project
          args[:project] = scope
          args[:additional_properties][:label] = 'project'
        else
          args[:additional_properties][:label] = 'instance'
        end

        args
      end

      def log_audit_event(message:)
        audit_context = {
          name: 'ci_runner_usage_export',
          author: @current_user,
          target: ::Gitlab::Audit::NullTarget.new,
          scope: scope || Gitlab::Audit::InstanceScope.new,
          message: message,
          additional_details: {
            runner_type: @runner_type,
            from_date: @from_date.iso8601,
            to_date: @to_date.iso8601
          }
        }

        ::Gitlab::Audit::Auditor.audit(audit_context)
      end
    end
  end
end
