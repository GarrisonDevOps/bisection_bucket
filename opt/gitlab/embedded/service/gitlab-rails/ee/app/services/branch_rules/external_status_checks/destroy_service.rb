# frozen_string_literal: true

module BranchRules
  module ExternalStatusChecks
    class DestroyService < BaseService
      private

      def execute_on_branch_rule
        ::ExternalStatusChecks::DestroyService.new(
          container: project,
          current_user: current_user,
          params: params
        ).execute
      end
      alias_method :execute_on_all_branches_rule, :execute_on_branch_rule
    end
  end
end
