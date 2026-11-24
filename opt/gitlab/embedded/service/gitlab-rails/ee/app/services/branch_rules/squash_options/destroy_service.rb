# frozen_string_literal: true

# rubocop:disable Gitlab/BoundedContexts -- TODO include branch rules bounded context
module BranchRules
  module SquashOptions
    class DestroyService < BaseService
      private

      def authorized?
        can?(current_user, :delete_squash_option, authorization_target)
      end

      def execute_on_branch_rule
        return not_found_error unless squash_option_record

        squash_option_record.destroy!

        ServiceResponse.success
      end

      def execute_on_all_branches_rule
        ServiceResponse.error(message: 'Deleting on an all branches rule is not supported')
      end

      def squash_option_record
        protected_branch&.squash_option
      end

      def authorization_target
        return squash_option_record if branch_rule? && squash_option_record

        branch_rule
      end
    end
  end
end
# rubocop:enable Gitlab/BoundedContexts
