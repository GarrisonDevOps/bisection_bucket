# frozen_string_literal: true

module EE
  module BranchRules # rubocop:disable Gitlab/BoundedContexts -- TODO include branch rules bounded context
    module SquashOptions
      module UpdateService
        extend ::Gitlab::Utils::Override

        private

        override :execute_on_branch_rule
        def execute_on_branch_rule
          record = squash_option_record
          record.squash_option = squash_option

          return ServiceResponse.error(message: record.errors.full_messages) unless record.save

          success_response
        end

        def squash_option_record
          protected_branch.squash_option ||
            ::Projects::BranchRules::SquashOption.new(
              project: project,
              protected_branch: protected_branch
            )
        end
      end
    end
  end
end
