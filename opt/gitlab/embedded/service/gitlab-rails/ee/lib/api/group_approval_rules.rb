# frozen_string_literal: true

module API
  class GroupApprovalRules < ::API::Base
    include PaginationParams

    before { authenticate! }
    before { check_feature_availability }
    before { check_feature_flag }

    helpers ::API::Helpers::GroupApprovalRulesHelpers

    feature_category :security_policy_management

    params do
      requires :id, type: String, desc: 'ID or URL-encoded path of the group.'
    end
    resource :groups, requirements: ::API::NAMESPACE_OR_PROJECT_REQUIREMENTS do
      segment ':id/approval_rules' do
        desc 'List all approval rules for a group' do
          detail 'Lists all approval rules and any associated details for a specified group. ' \
            'Restricted to group administrators. ' \
            'Use the `page` and `per_page` pagination parameters to restrict the list of approval rules. ' \
            'This feature was introduced in GitLab 16.10.'
          success ::API::Entities::GroupApprovalRule
          is_array true
          tags ['approval_rules']
        end
        params do
          use :pagination
        end
        route_setting :tier, :premium
        route_setting :authorization, permissions: :read_approval_rule, boundary_type: :group
        get do
          authorize! :read_approval_rule, user_group

          group_approval_rules = paginate(user_group.approval_rules)

          present group_approval_rules, with: ::API::Entities::GroupApprovalRule
        end

        desc 'Create an approval rule for a group' do
          detail 'Creates an approval rule for a group. Restricted to group administrators. ' \
            'Do not use the `rule_type` field when building approval rules from the API. ' \
            'The field supports these rule types: `any_approver`, a pre-configured default rule ' \
            'with `approvals_required` set to `0`; `regular`, for regular merge request approval rules; and ' \
            '`report_approver`, used when GitLab creates an approval rule from configured and enabled merge ' \
            'request approval policies.'
          success ::API::Entities::GroupApprovalRule
          tags ['approval_rules']
        end
        params do
          requires :name, type: String, desc: 'Name of the approval rule. Limited to 1024 characters.'
          requires :approvals_required, type: Integer, desc: 'Number of required approvals for the rule.'
          use :group_approval_rule
        end
        route_setting :tier, :premium
        route_setting :authorization, permissions: :create_approval_rule, boundary_type: :group
        post do
          create_group_approval_rule(present_with: ::API::Entities::GroupApprovalRule)
        end

        params do
          requires :approval_rule_id, type: Integer, desc: 'ID of the group approval rule.'
        end

        params do
          optional :name, type: String, desc: 'Name of the approval rule. Limited to 1024 characters.'
          optional :approvals_required, type: Integer, desc: 'Number of required approvals for the rule.'
          use :group_approval_rule
        end

        desc 'Update group approval rule' do
          detail 'Updates an approval rule for a group. Restricted to group administrators. Do not use the ' \
            '`rule_type` field when building approval rules from the API. The field supports these rule types: ' \
            '`any_approver`, a pre-configured default ' \
            'rule with `approvals_required` set to `0`; `regular`, for regular merge request approval rules; and ' \
            '`report_approver`, used when GitLab creates an approval rule from configured and enabled merge ' \
            'request approval policies. This feature was introduced in GitLab 16.10.'
          success ::API::Entities::GroupApprovalRule
          tags ['approval_rules']
        end
        route_setting :tier, :premium
        route_setting :authorization, permissions: :update_approval_rule, boundary_type: :group
        put ':approval_rule_id' do
          update_group_approval_rule(present_with: ::API::Entities::GroupApprovalRule)
        end
      end
    end
  end
end
