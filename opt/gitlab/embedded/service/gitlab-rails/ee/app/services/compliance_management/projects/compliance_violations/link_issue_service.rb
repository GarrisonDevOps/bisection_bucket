# frozen_string_literal: true

module ComplianceManagement
  module Projects
    module ComplianceViolations
      class LinkIssueService < BaseService
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

          if violation.issues.include?(issue)
            return ServiceResponse.error(
              message: "Issue ID #{issue.id} is already linked to violation ID #{violation.id}"
            )
          end

          link_record = ComplianceManagement::Projects::ComplianceViolationIssue.new(issue: issue,
            project_compliance_violation: violation, project: violation.project)

          if link_record.save
            create_system_note
            return ServiceResponse.success
          end

          ServiceResponse.error(message: "Failed to link issue: #{link_record.errors.full_messages.join(', ')}")
        end

        private

        attr_reader :current_user, :violation, :issue

        def allowed?
          Ability.allowed?(current_user, :update_compliance_violations_report, violation) &&
            Ability.allowed?(current_user, :read_issue, issue)
        end

        def create_system_note
          ::SystemNotes::ComplianceViolationsService.new(
            container: violation.project,
            noteable: violation,
            author: current_user).link_issue(issue)
        end
      end
    end
  end
end
