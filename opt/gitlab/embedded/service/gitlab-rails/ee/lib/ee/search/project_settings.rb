# frozen_string_literal: true

module EE
  module Search
    module ProjectSettings
      extend ActiveSupport::Concern

      extend ::Gitlab::Utils::Override

      override :general_settings
      def general_settings
        settings = super

        if project.licensed_ai_features_available?
          settings.push({ text: _("GitLab Duo"), href: edit_project_path(project, anchor: 'js-gitlab-duo-settings') })
        end

        if project.licensed_feature_available?(:issuable_default_templates)
          settings.push({ text: s_('WorkItem|Default description for work items'),
            href: edit_project_path(project, anchor: 'js-issue-settings') })
        end

        settings
      end

      override :repository_settings
      def repository_settings
        settings = super

        if ::Gitlab::Saas.feature_available?(:repositories_web_based_commit_signing)
          settings.push(
            { text: _('General'), href: project_settings_repository_path(project, anchor: 'js-general-settings') }
          )
        end

        if project.licensed_feature_available?(:target_branch_rules)
          settings.push(
            { text: _("Protected branches"),
              href: project_settings_repository_path(project, anchor: 'js-protected-branches-settings') },
            { text: _("Protected tags"),
              href: project_settings_repository_path(project, anchor: 'js-protected-tags-settings') }
          )
        end

        if project.licensed_feature_available?(:push_rules)
          settings.push({
            text: s_('PushRule|Push rules'),
            href: project_settings_repository_path(project, anchor: 'js-push-rules')
          })
        end

        settings
      end

      override :merge_request_settings
      def merge_request_settings
        settings = super

        if project.licensed_feature_available?(:target_branch_rules)
          settings.push({
            text: _("Merge request branch workflow"),
            href: project_settings_merge_requests_path(project, anchor: 'target-branch-rules')
          })
        end

        if project.licensed_feature_available?(:merge_request_approvers)
          settings.push({
            text: _("Merge request approvals"),
            href: project_settings_merge_requests_path(project, anchor: 'js-merge-request-approval-settings')
          })
        end

        if ::Gitlab::Duo::CodeReview.automatic_review_available?(project)
          settings.push({
            text: s_("DuoCodeReview|GitLab Duo Code Review"),
            href: project_settings_merge_requests_path(project, anchor: 'merge-request-duo-code-review-settings')
          })
        end

        settings
      end

      override :ci_cd_settings
      def ci_cd_settings
        settings = super

        if project.licensed_feature_available?(:protected_environments)
          settings.push({
            text: _("Protected environments"),
            href: project_settings_ci_cd_path(project, anchor: 'js-protected-environments-settings')
          })
        end

        if project.licensed_feature_available?(:auto_rollback)
          settings.push({
            text: _("Automatic deployment rollbacks"),
            href: project_settings_ci_cd_path(project, anchor: 'auto-rollback-settings')
          })
        end

        if project.licensed_feature_available?(:ci_project_subscriptions)
          settings.push({
            text: _("Pipeline subscriptions"),
            href: project_settings_ci_cd_path(project, anchor: 'pipeline-subscriptions')
          })
        end

        settings
      end

      override :monitor_settings
      def monitor_settings
        settings = super

        if project.licensed_feature_available?(:observability)
          settings.push({
            text: s_('Observability|Tracing, Metrics & Logs'),
            href: project_settings_operations_path(project, anchor: 'js-observability-settings')
          })
        end

        if project.licensed_feature_available?(:status_page)
          settings.push(
            { text: s_("StatusPage|Status page"),
              href: project_settings_operations_path(project, anchor: 'status-page') }
          )
        end

        settings
      end
    end
  end
end
