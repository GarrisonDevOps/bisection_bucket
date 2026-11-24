# frozen_string_literal: true

module ComplianceManagement
  module Groups
    module ComplianceViolations
      class ExportService
        BATCH_SIZE = 25
        TARGET_FILESIZE = 15.megabytes
        CSV_ASSOCIATIONS = [:project, :namespace, :compliance_control].freeze

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
          ComplianceManagement::Groups::ComplianceViolationsExportMailerWorker.perform_async(user.id, group.id)

          ServiceResponse.success
        end

        private

        attr_reader :user, :group

        def csv_builder
          @csv_builder ||= CsvBuilder.new(rows, csv_header, CSV_ASSOCIATIONS)
        end

        def allowed?
          Ability.allowed?(user, :read_compliance_violations_report, group)
        end

        def model
          ::ComplianceManagement::Projects::ComplianceViolation
        end

        def rows
          scope = ::ComplianceManagement::Projects::ComplianceViolation.unscoped

          opts = {
            in_operator_optimization_options: {
              array_scope: group.self_and_descendant_ids,
              array_mapping_scope: model.method(:in_optimization_array_mapping_scope)
            }
          }

          ids = Set.new
          Gitlab::Pagination::Keyset::Iterator.new(scope: scope, **opts).each_batch(of: BATCH_SIZE) do |records|
            # Using pluck here is safe IMHO, already batching with batch size 25, and we only need the ids -> pluck
            ids.merge records.pluck(:id) # rubocop:disable CodeReuse/ActiveRecord, Database/AvoidUsingPluckWithoutLimit -- see above
          end

          # result w/ sort should be fine index on created_at, id exists
          ::ComplianceManagement::Projects::ComplianceViolation
            .id_in(ids.to_a)
            .including_controls
            .order_by_created_at_and_id(:desc)
        end

        def csv_header
          {
            "Detected at" => ->(violation) { violation.created_at&.strftime('%Y-%m-%d %H:%M:%S') },
            "Violation ID" => 'id',
            "Status" => 'status',
            "Framework" => ->(violation) { violation.framework&.name },
            "Compliance Control" => ->(violation) { violation.compliance_control&.name },
            "Compliance Requirement" => ->(violation) { violation.requirement&.name },
            "Audit Event ID" => ->(violation) { violation.audit_event&.id },
            "Audit Event Author" => ->(violation) { violation.audit_event&.author&.name },
            "Audit Event Type" => ->(violation) { violation.audit_event&.entity_type },
            "Audit Event Name" => ->(violation) { violation.audit_event&.event_name },
            "Audit Event Message" => ->(violation) {
              details = violation.audit_event&.details
              details&.dig(:custom_message) || details&.to_s
            },
            "Project ID" => 'project_id'
          }
        end
      end
    end
  end
end
