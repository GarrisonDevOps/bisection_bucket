# frozen_string_literal: true

module ComplianceManagement
  module ComplianceFramework
    module ProjectRequirementStatuses
      class ExportService
        TARGET_FILESIZE = 15.megabytes
        CSV_ASSOCIATIONS = [
          :compliance_framework,
          :compliance_requirement,
          :project,
          { control_statuses: :compliance_requirements_control }
        ].freeze
        BATCH_SIZE = 1000
        MAX_ROWS = 10_000

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
          ProjectRequirementStatusesExportMailerWorker.perform_async(user.id, group.id)

          ServiceResponse.success
        end

        private

        attr_reader :user, :group

        def csv_builder
          @csv_builder ||= CsvBuilder.new(rows, csv_header, CSV_ASSOCIATIONS)
        end

        def allowed?
          Ability.allowed?(user, :read_compliance_adherence_report, group)
        end

        def rows
          Enumerator.new do |yielder|
            count = 0
            iterator.each_batch(of: BATCH_SIZE) do |batch|
              break if count >= MAX_ROWS

              records = load_batch_with_associations(batch)
              records.each do |record|
                break if count >= MAX_ROWS

                yielder << record
                count += 1
              end
            end
          end
        end

        def iterator
          scope = finder.execute
          Gitlab::Pagination::Keyset::Iterator.new(scope: scope)
        end

        def finder
          ::ComplianceManagement::ComplianceFramework::ProjectRequirementStatusFinder.new(
            group, user, skip_limit: true
          )
        end

        def load_batch_with_associations(batch)
          records = batch.to_a
          ActiveRecord::Associations::Preloader.new(
            records: records,
            associations: CSV_ASSOCIATIONS
          ).call
          records
        end

        def model
          ::ComplianceManagement::ComplianceFramework::ProjectRequirementComplianceStatus
        end

        def csv_header
          {
            "Passed" => 'pass_count',
            "Failed" => 'fail_count',
            "Pending" => 'pending_count',
            "Requirement" => ->(status) { status.compliance_requirement.name },
            "Framework" => ->(status) { status.compliance_framework.name },
            "Project ID" => 'project_id',
            "Project name" => ->(status) { status.project.name },
            "Date of last update" => 'updated_at',
            "Control Statuses" => ->(status) {
              status.control_statuses.map do |control|
                "#{control.compliance_requirements_control.name}:#{control.status} "
              end.join(" ")
            }
          }
        end
      end
    end
  end
end
