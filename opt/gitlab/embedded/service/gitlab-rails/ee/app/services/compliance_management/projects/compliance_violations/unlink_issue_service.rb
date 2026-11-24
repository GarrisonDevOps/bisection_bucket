# frozen_string_literal: true

module ComplianceManagement
  module Projects
    module ComplianceViolations
      class UnlinkIssueService < BaseService
        def initialize(current_user:, violation:, issue:)
          @current_user = current_user
          @violation = violation
          @issue = issue
        end

        def execute
          if issue.nil? || violation.nil?
            return ServiceResponse.error(message: "Issue and violation should be non nil.")
          end

          return ServiceResponse.error(message: "Access denied for user id: #{current_user&.id}") unless allowed?

          unless violation.issues.include?(issue)
            return ServiceResponse.error(message: "Issue ID #{issue.id} is not linked to violation ID #{violation.id}")
          end

          if violation.issues.destroy(issue)
            create_system_note
            return ServiceResponse.success
          end

          Gitlab::ErrorTracking.track_and_raise_exception(
            StandardError.new("Failed to unlink issue from violation: #{issue.errors.full_messages.join(', ')}"),
            { violation_id: violation.id, issue_id: issue.id }
          )
          ServiceResponse.error(message: "Failed to unlink issue")
        end

        private

        attr_reader :current_user, :violation, :issue

        def allowed?
          Ability.allowed?(current_user, :update_compliance_violations_report, violation)
        end

        def create_system_note
          ::SystemNotes::ComplianceViolationsService.new(
            container: violation.project,
            noteable: violation,
            author: current_user).unlink_issue(issue)
        end
      end
    end
  end
end
