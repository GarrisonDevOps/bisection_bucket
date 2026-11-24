# frozen_string_literal: true

module API
  module Helpers
    module ProjectApprovalRulesHelpers
      extend Grape::API::Helpers

      params :create_project_approval_rule do
        requires :name, type: String, desc: 'Name of the approval rule. Limited to 1024 characters.'
        requires :approvals_required, type: Integer, desc: 'Number of required approvals for the rule.'
        optional :rule_type, type: String, desc: 'Type of the approval rule. Possible values are `regular`, `report_approver`, and `any_approver`.', documentation: { example: 'regular' }
        optional :users, as: :user_ids, type: Array[Integer], coerce_with: ::API::Validations::Types::CommaSeparatedToIntegerArray.coerce, desc: 'IDs of users to add as approvers. Deprecated. Use `user_ids` instead.'
        optional :user_ids, type: Array[Integer], coerce_with: ::API::Validations::Types::CommaSeparatedToIntegerArray.coerce, desc: 'IDs of users to add as approvers. When used with `usernames`, both lists of users are added.'
        optional :groups, as: :group_ids, type: Array[Integer], coerce_with: ::API::Validations::Types::CommaSeparatedToIntegerArray.coerce, desc: 'IDs of groups to add as approvers. Deprecated. Use `group_ids` instead.'
        optional :group_ids, type: Array[Integer], coerce_with: ::API::Validations::Types::CommaSeparatedToIntegerArray.coerce, desc: 'IDs of groups to add as approvers.'
        optional :usernames, type: Array[String], coerce_with: ::API::Validations::Types::CommaSeparatedToArray.coerce, desc: 'Usernames of approvers. If used with `user_ids`, adds both lists of users.'
        optional :protected_branch_ids, type: Array[Integer], coerce_with: ::API::Validations::Types::CommaSeparatedToIntegerArray.coerce, desc: 'IDs of protected branches to scope the rule by.'
        optional :applies_to_all_protected_branches, default: false, type: Boolean, desc: 'If `true`, applies the rule to all protected branches and ignores the `protected_branch_ids` attribute.'
        optional :report_type, type: String, desc: 'Type of the report required when `rule_type` is set to `report_approver`.', values: %w[code_coverage]
        optional :coverage_minimum_threshold, type: Float, desc: 'Minimum code coverage percentage for the rule, from 0 to 100. If coverage falls below this threshold, approval is required.'
        optional :vulnerabilities_allowed, type: Integer, desc: 'Number of vulnerabilities allowed for the rule.'
        optional :scanners,
          type: Array[String],
          desc: 'Security scanners to be considered by the approval rule.',
          documentation: { example: ApprovalProjectRule::SUPPORTED_SCANNERS }
        optional :severity_levels,
          type: Array[String],
          desc: 'Security levels to be considered by the approval rule.',
          documentation: { example: ApprovalProjectRule::DEFAULT_SEVERITIES }
        optional :vulnerability_states,
          type: Array[String],
          desc: 'Vulnerability states to be considered by the approval rule.',
          documentation: { example: ApprovalProjectRule::APPROVAL_VULNERABILITY_STATES }
      end

      params :update_project_approval_rule do
        requires :approval_rule_id, type: Integer, desc: 'ID of the approval rule.'
        optional :name, type: String, desc: 'Name of the approval rule. Limited to 1024 characters.'
        optional :approvals_required, type: Integer, desc: 'Number of required approvals for the rule.'
        optional :users, as: :user_ids, type: Array[Integer], coerce_with: ::API::Validations::Types::CommaSeparatedToIntegerArray.coerce, desc: 'IDs of users to add as approvers. Deprecated. Use `user_ids` instead.'
        optional :user_ids, type: Array[Integer], coerce_with: ::API::Validations::Types::CommaSeparatedToIntegerArray.coerce, desc: 'IDs of users to add as approvers. When used with `usernames`, both lists of users are added.'
        optional :groups, as: :group_ids, type: Array[Integer], coerce_with: ::API::Validations::Types::CommaSeparatedToIntegerArray.coerce, desc: 'IDs of groups to add as approvers. Deprecated. Use `group_ids` instead.'
        optional :group_ids, type: Array[Integer], coerce_with: ::API::Validations::Types::CommaSeparatedToIntegerArray.coerce, desc: 'IDs of groups to add as approvers.'
        optional :usernames, type: Array[String], coerce_with: ::API::Validations::Types::CommaSeparatedToArray.coerce, desc: 'Usernames of approvers. If used with `user_ids`, adds both lists of users.'
        optional :protected_branch_ids, type: Array[Integer], coerce_with: ::API::Validations::Types::CommaSeparatedToIntegerArray.coerce, desc: 'IDs of protected branches to scope the rule by.'
        optional :applies_to_all_protected_branches, type: Boolean, desc: 'If `true`, applies the rule to all protected branches and ignores the `protected_branch_ids` attribute.'
        optional :remove_hidden_groups, type: Boolean, desc: 'If `true`, removes hidden groups from the approval rule.'
        optional :coverage_minimum_threshold, type: Float, desc: 'Minimum code coverage percentage for the rule, from 0 to 100. If coverage falls below this threshold, approval is required.'
        optional :vulnerabilities_allowed, type: Integer, desc: 'Number of vulnerabilities allowed for the rule.'
        optional :scanners,
          type: Array[String],
          desc: 'Security scanners to be considered by the approval rule.',
          documentation: { example: ApprovalProjectRule::SUPPORTED_SCANNERS }
        optional :severity_levels,
          type: Array[String],
          desc: 'Security levels to be considered by the approval rule.',
          documentation: { example: ApprovalProjectRule::DEFAULT_SEVERITIES }
        optional :vulnerability_states,
          type: Array[String],
          desc: 'Vulnerability states to be considered by the approval rule.',
          documentation: { example: ApprovalProjectRule::APPROVAL_VULNERABILITY_STATES }
      end

      params :delete_project_approval_rule do
        requires :approval_rule_id, type: Integer, desc: 'ID of the approval rule.'
      end

      def check_feature_availability
        forbidden! unless ::License.feature_available?(:merge_request_approvers)
      end

      def authorize_read_project_approval_rule!
        return if can?(current_user, :manage_merge_request_settings, user_project)

        authorize! :create_merge_request_in, user_project
      end

      def create_project_approval_rule(present_with:)
        authorize! :manage_merge_request_settings, user_project
        authorize! :modify_approvers_rules, user_project

        result = ::ApprovalRules::CreateService.new(user_project, current_user, declared_params(include_missing: false)).execute

        if result.success?
          present result[:rule], with: present_with, current_user: current_user
        else
          render_api_error!(result.message, result.cause.access_denied? ? 403 : 400)
        end
      end

      def update_project_approval_rule(present_with:)
        authorize! :manage_merge_request_settings, user_project
        authorize! :modify_approvers_rules, user_project

        params = declared_params(include_missing: false)
        approval_rule = user_project.approval_rules.not_from_scan_result_policy.find(params.delete(:approval_rule_id))

        result = ::ApprovalRules::UpdateService.new(approval_rule, current_user, params).execute

        if result.success?
          present result[:rule], with: present_with, current_user: current_user
        else
          render_api_error!(result.message, result.cause.access_denied? ? 403 : 400)
        end
      end

      def destroy_project_approval_rule
        authorize! :manage_merge_request_settings, user_project
        authorize! :modify_approvers_rules, user_project

        approval_rule = user_project.approval_rules.not_from_scan_result_policy.find(params[:approval_rule_id])

        destroy_conditionally!(approval_rule) do |rule|
          ::ApprovalRules::ProjectRuleDestroyService.new(rule, current_user).execute
        end
      end
    end
  end
end
