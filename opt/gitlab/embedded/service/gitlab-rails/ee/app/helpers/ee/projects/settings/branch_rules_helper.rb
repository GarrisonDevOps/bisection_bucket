# frozen_string_literal: true

module EE
  module Projects
    module Settings
      module BranchRulesHelper
        def group_protected_branches_licensed_and_can_admin?(project)
          namespace = project.root_ancestor

          namespace.is_a?(Group) &&
            group_protected_branches_feature_available?(namespace) &&
            Ability.allowed?(current_user, :admin_group, namespace)
        end

        def group_branch_rules_path(project)
          namespace = project.root_ancestor
          return '' unless namespace.is_a?(Group)

          group_settings_repository_path(namespace, anchor: 'js-protected-branches-settings')
        end

        def branch_rules_data(project)
          show_status_checks = project.licensed_feature_available?(:external_status_checks) &&
            can?(current_user, :read_external_status_check, project)
          show_approvers = project.licensed_feature_available?(:merge_request_approvers) &&
            can?(current_user, :manage_merge_request_settings, project)
          show_code_owners = project.licensed_feature_available?(:code_owner_approval_required)
          show_enterprise_access_levels = project.licensed_feature_available?(:protected_refs_for_users)
          {
            project_path: project.full_path,
            protected_branches_path: project_settings_repository_path(project,
              anchor: 'js-protected-branches-settings'),
            branch_rules_path: project_settings_repository_path(project, anchor: 'branch-rules'),
            branches_path: project_branches_path(project),
            show_status_checks: show_status_checks.to_s,
            show_approvers: show_approvers.to_s,
            show_code_owners: show_code_owners.to_s,
            show_enterprise_access_levels: show_enterprise_access_levels.to_s,
            custom_roles_licensed: project.root_ancestor&.licensed_feature_available?(:custom_roles).to_s,
            project_id: project.id,
            rules_path: expose_path(api_v4_projects_approval_rules_path(id: project.id)),
            can_edit: can?(current_user, :modify_approvers_rules, project).to_s,
            allow_multi_rule: project.multiple_approval_rules_available?.to_s,
            can_admin_protected_branches: can?(current_user, :update_protected_branch, project).to_s,
            can_delete_custom_branch_rule: can?(current_user, :delete_branch_rule,
              ::Projects::AllProtectedBranchesRule.new(project)).to_s,
            can_read_protected_branches: can?(current_user, :read_protected_branch, project).to_s,
            can_read_squash_option: can?(current_user, :read_squash_option, project).to_s,
            can_update_squash_option: can?(current_user, :update_squash_option, project).to_s,
            can_admin_group_protected_branches: group_protected_branches_licensed_and_can_admin?(project).to_s,
            group_settings_repository_path: group_branch_rules_path(project),
            security_policies_path: security_policies_path(project)
          }
        end
      end
    end
  end
end
