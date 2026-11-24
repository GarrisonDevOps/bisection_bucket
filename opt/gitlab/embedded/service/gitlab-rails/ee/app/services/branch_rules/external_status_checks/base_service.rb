# frozen_string_literal: true

# rubocop:disable Gitlab/BoundedContexts -- TODO include branch rules bounded context
module BranchRules
  module ExternalStatusChecks
    class BaseService < ::BranchRules::BaseService
      private

      def execute_on_all_branches_rule
        ServiceResponse.error(
          message: 'All branch rules cannot configure external status checks',
          payload: { errors: ['All branch rules not allowed'] },
          reason: :unprocessable_entity
        )
      end

      def execute_on_all_protected_branches_rule
        ServiceResponse.error(
          message: 'All protected branch rules cannot configure external status checks',
          payload: { errors: ['All protected branches not allowed'] },
          reason: :unprocessable_entity
        )
      end

      def authorized?
        true
      end
    end
  end
end
# rubocop:enable Gitlab/BoundedContexts
