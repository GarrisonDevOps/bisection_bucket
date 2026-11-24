# frozen_string_literal: true

module ComplianceManagement
  module ComplianceFramework
    module ComplianceRequirements
      class RefreshStatusService < BaseService
        RefreshStatusError = Class.new StandardError

        def initialize(requirement_status)
          @requirement_status = requirement_status
        end

        def execute
          return error(_('Requirement status is nil.')) if requirement_status.nil?
          return error(_('Not permitted to refresh compliance requirement status')) unless permitted?

          refresh_status
          success
        rescue RefreshStatusError => e
          Gitlab::ErrorTracking.log_exception(e, requirement_status: requirement_status.id,
            requirement: requirement_status.compliance_requirement_id, project: requirement_status.project_id)
          error(e.message)
        end

        private

        attr_reader :requirement_status

        def permitted?
          requirement_status.project.licensed_feature_available?(:custom_compliance_frameworks)
        end

        def refresh_status
          status_counts = requirement_status.control_status_values.tally

          if status_counts.values.sum == 0
            requirement_status.destroy

            return if requirement_status.destroyed?

            raise RefreshStatusError, requirement_status.errors.full_messages.join(",")
          end

          return if requirement_status.update(
            pass_count: status_counts.fetch("pass", 0),
            fail_count: status_counts.fetch("fail", 0),
            pending_count: status_counts.fetch("pending", 0),
            not_applicable_count: status_counts.fetch("not_applicable", 0),
            updated_at: Time.current
          )

          raise RefreshStatusError, requirement_status.errors.full_messages.join(",")
        end

        def success
          ServiceResponse.success(message: _('Compliance requirement status successfully refreshed.'))
        end

        def error(error_message)
          ServiceResponse.error(
            message: format(
              _("Failed to refresh compliance requirement status. Error: %{error_message}"),
              error_message: error_message
            )
          )
        end
      end
    end
  end
end
