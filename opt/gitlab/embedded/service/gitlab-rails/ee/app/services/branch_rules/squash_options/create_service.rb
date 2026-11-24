# frozen_string_literal: true

# rubocop:disable Gitlab/BoundedContexts -- TODO include branch rules bounded context
module BranchRules
  module SquashOptions
    class CreateService < BaseService
      private

      def authorized?
        can?(current_user, :create_squash_option, branch_rule)
      end

      def execute_on_branch_rule
        record = ::Projects::BranchRules::SquashOption.create(
          protected_branch: protected_branch,
          project: project,
          squash_option: squash_option
        )

        return ServiceResponse.error(message: record.errors.full_messages) if record.errors.any?

        ServiceResponse.success(payload: record)
      end
    end
  end
end
# rubocop:enable Gitlab/BoundedContexts
