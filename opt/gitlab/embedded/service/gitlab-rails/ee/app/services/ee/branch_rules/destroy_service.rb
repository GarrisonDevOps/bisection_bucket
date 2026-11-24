# frozen_string_literal: true

module EE
  module BranchRules
    module DestroyService
      private

      def execute_on_all_branches_rule
        if project.licensed_feature_available?(:multiple_approval_rules)
          response = destroy_approval_project_rules

          return response if response.error?
        end

        return ::ServiceResponse.success unless project.licensed_feature_available?(:external_status_checks)

        destroy_external_status_checks
      end

      def execute_on_all_protected_branches_rule
        destroy_approval_project_rules
      end

      def destroy_approval_project_rules
        errors = approval_project_rules.find_each.each_with_object([]) do |rule, error_accumulator|
          response = ::ApprovalRules::ProjectRuleDestroyService.new(rule, current_user).execute

          error_accumulator << response if response.error?
        end

        return ::ServiceResponse.success if errors.blank?

        ::ServiceResponse.error(message: "Failed to delete approval #{'rule'.pluralize(errors.count)}.")
      end

      def destroy_external_status_checks
        errors = external_status_checks.find_each.each_with_object([]) do |check, error_accumulator|
          response = ::ExternalStatusChecks::DestroyService.new(
            container: project, current_user: current_user, params: { id: check.id }
          ).execute

          error_accumulator << response if response.error?
        end

        return ::ServiceResponse.success if errors.blank?

        ::ServiceResponse.error(message: "Failed to delete external status #{'check'.pluralize(errors.count)}.")
      end
    end
  end
end
