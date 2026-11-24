# frozen_string_literal: true

module ComplianceManagement
  module Standards
    class ExportService
      TARGET_FILESIZE = 15.megabytes

      def initialize(user:, group:)
        @user = user
        @group = group
      end

      def execute
        return ServiceResponse.error(message: 'namespace must be a group') unless group.is_a?(Group)
        return ServiceResponse.error(message: "Access to group denied for user with ID: #{user.id}") unless allowed?

        ServiceResponse.success(payload: csv_builder.render(TARGET_FILESIZE))
      end

      def email_export
        StandardsAdherenceExportMailerWorker.perform_async(user.id, group.id)

        ServiceResponse.success
      end

      private

      attr_reader :user, :group

      def csv_builder
        @csv_builder ||= CsvBuilder.new(rows, csv_header)
      end

      def allowed?
        Ability.allowed?(user, :read_compliance_adherence_report, group)
      end

      def rows
        ::Projects::ComplianceStandards::AdherenceFinder.new(group, user, { include_subgroups: true }).execute
      end

      def csv_header
        {
          'Status' => 'status',
          'Project ID' => 'project_id',
          'Check' => 'check_name',
          'Standard' => 'standard',
          'Date since last status change' => 'updated_at'
        }
      end
    end
  end
end
