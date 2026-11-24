# frozen_string_literal: true

module WorkItems
  module Callbacks
    class VerificationStatus < Base
      def before_update
        return remove_test_report_associations if excluded_in_new_type?

        return unless has_permission?(:create_requirement_test_report)
        return unless params&.has_key?(:verification_status)

        status_param = params[:verification_status]

        test_report =
          RequirementsManagement::TestReport.build_report(
            requirement_issue: work_item,
            state: status_param,
            author: current_user
          )

        work_item.touch if test_report.save
      end

      private

      def remove_test_report_associations
        test_reports = work_item.test_reports
        return if test_reports.empty?

        work_item.requirement.destroy
        work_item.touch
      end
    end
  end
end
