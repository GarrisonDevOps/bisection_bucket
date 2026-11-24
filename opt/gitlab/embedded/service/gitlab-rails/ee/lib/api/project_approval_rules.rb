# frozen_string_literal: true

module API
  class ProjectApprovalRules < ::API::Base
    include PaginationParams

    before { authenticate! }
    before { check_feature_availability }

    helpers ::API::Helpers::ProjectApprovalRulesHelpers

    feature_category :source_code_management

    params do
      requires :id, types: [String, Integer], desc: 'ID or URL-encoded path of the project.'
    end
    resource :projects, requirements: ::API::NAMESPACE_OR_PROJECT_REQUIREMENTS do
      segment ':id/approval_rules' do
        desc 'List all approval rules for a project' do
          detail 'Lists all approval rules and any associated details for a specified project. To restrict the list ' \
            'of approval rules, use the `page` and `per_page` pagination parameters. Each rule in the response ' \
            'includes `eligible_approvers`, the users who can approve a merge request the rule applies to. ' \
            'Eligible approvers depend on the rule configuration and on project and group membership.'
          success ::API::Entities::ProjectApprovalRule
          is_array true
          tags %w[approval_rules]
        end
        params do
          use :pagination
        end
        route_setting :tier, :premium
        route_setting :authorization, permissions: :read_approval_rule, boundary_type: :project
        get do
          authorize_read_project_approval_rule!

          present paginate(::Kaminari.paginate_array(user_project.visible_approval_rules)), with: ::API::Entities::ProjectApprovalRule, current_user: current_user
        end

        desc 'Create an approval rule for a project' do
          detail 'Creates an approval rule for a specified project. The `rule_type` field supports these rule ' \
            'types: `any_approver`, a pre-configured default rule with `approvals_required` set to `0`; ' \
            '`regular`, for regular merge request approval rules; and `report_approver`, used when GitLab ' \
            'creates an approval rule from configured and enabled merge request approval policies. Do not use ' \
            '`report_approver` when creating approval rules with this API.'
          success ::API::Entities::ProjectApprovalRule
          tags %w[approval_rules]
        end
        params do
          use :create_project_approval_rule
        end
        route_setting :tier, :premium
        route_setting :authorization, permissions: :create_approval_rule, boundary_type: :project
        post do
          create_project_approval_rule(present_with: ::API::Entities::ProjectApprovalRule)
        end

        params do
          requires :approval_rule_id, type: Integer, desc: 'ID of the approval rule.'
        end
        segment ':approval_rule_id' do
          desc 'Retrieve an approval rule for a project' do
            detail 'Retrieves information about a specified approval rule for a project.'
            success ::API::Entities::ProjectApprovalRule
            tags %w[approval_rules]
          end
          route_setting :tier, :premium
          route_setting :authorization, permissions: :read_approval_rule, boundary_type: :project
          get do
            authorize_read_project_approval_rule!

            approval_rule = user_project.approval_rules.find(params[:approval_rule_id])

            present approval_rule, with: ::API::Entities::ProjectApprovalRule, current_user: current_user
          end

          desc 'Update an approval rule for a project' do
            detail 'Updates a specified approval rule for a project. This endpoint removes any approvers and groups ' \
              'not defined in the `group_ids`, `user_ids`, or `usernames` attributes. Hidden groups (private groups ' \
              'the user does not have permission to view) that are not in the `users` or `groups` parameters are ' \
              'preserved by default. To remove them, set `remove_hidden_groups` to `true`. This ensures hidden ' \
              'groups are not removed unintentionally when a user updates an approval rule.'
            success ::API::Entities::ProjectApprovalRule
            tags %w[approval_rules]
          end
          params do
            use :update_project_approval_rule
          end
          route_setting :tier, :premium
          route_setting :authorization, permissions: :update_approval_rule, boundary_type: :project
          put do
            update_project_approval_rule(present_with: ::API::Entities::ProjectApprovalRule)
          end

          desc 'Delete an approval rule for a project' do
            detail 'Deletes an approval rule for a specified project.'
            success [{ code: 204 }]
            tags %w[approval_rules]
          end
          params do
            use :delete_project_approval_rule
          end
          route_setting :tier, :premium
          route_setting :authorization, permissions: :delete_approval_rule, boundary_type: :project
          delete do
            destroy_project_approval_rule
          end
        end
      end
    end
  end
end
