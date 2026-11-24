# frozen_string_literal: true

module BranchRules
  module ExternalStatusChecks
    class UpdateService < BaseService
      private

      def execute_on_branch_rule
        update_external_status_check(params.merge(protected_branch_ids: [branch_rule.id]))
      end

      def execute_on_all_branches_rule
        update_external_status_check(params)
      end

      def update_external_status_check(esc_params)
        ::ExternalStatusChecks::UpdateService.new(
          container: project,
          current_user: current_user,
          params: esc_params
        ).execute
      end
    end
  end
end
