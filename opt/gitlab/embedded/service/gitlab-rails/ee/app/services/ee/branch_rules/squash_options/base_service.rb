# frozen_string_literal: true

module EE
  module BranchRules # rubocop:disable Gitlab/BoundedContexts -- TODO include branch rules bounded context
    module SquashOptions
      module BaseService
        extend ::Gitlab::Utils::Override

        override :execute_on_branch_rule_type
        def execute_on_branch_rule_type
          return feature_not_available_error if branch_rule_requires_license?

          super
        end

        private

        def branch_rule_requires_license?
          branch_rule.instance_of?(::Projects::BranchRule) &&
            !project.licensed_feature_available?(:branch_rule_squash_options)
        end

        def feature_not_available_error
          ServiceResponse.error(message: 'Squash options are not available for this branch rule')
        end
      end
    end
  end
end
