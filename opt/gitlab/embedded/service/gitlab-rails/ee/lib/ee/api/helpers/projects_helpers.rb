# frozen_string_literal: true

module EE
  module API
    module Helpers
      module ProjectsHelpers
        extend ActiveSupport::Concern
        extend ::Gitlab::Utils::Override

        prepended do
          params :optional_create_project_params_ee do
            optional :use_custom_template, type: Grape::API::Boolean, desc: "Use a custom instance-level project template, or a group-level one with `group_with_project_templates_id`. Premium and Ultimate only."
            given :use_custom_template do
              optional :group_with_project_templates_id, type: Integer, desc: "For group-level custom templates, ID of the group that serves as the template source. Leave empty for instance-level templates. Requires `use_custom_template` to be `true`. Premium and Ultimate only."
            end
          end

          params :optional_project_params_ee do
            optional :only_allow_merge_if_all_status_checks_passed, type: Grape::API::Boolean, desc: 'Blocks merge requests from merging unless all status checks have passed. Default is `false`. Ultimate only.'
            optional :approvals_before_merge, type: Integer, desc: 'How many approvers should approve merge request by default. Deprecated in GitLab 16.0: Use the merge request approvals API instead. Premium and Ultimate only.', allow_blank: false
            optional :mirror, type: Grape::API::Boolean, desc: '[Deprecated] Enables pull mirroring in a project. Premium and Ultimate only.'
            optional :mirror_trigger_builds, type: Grape::API::Boolean, desc: '[Deprecated] Pull mirroring triggers builds. Premium and Ultimate only.'
            optional :external_authorization_classification_label, type: String, desc: 'The classification label for the project. Premium and Ultimate only.'
            optional :requirements_access_level, type: String, values: %w[disabled private enabled], desc: 'Requirements feature access level. One of `disabled`, `private` or `enabled`'
            optional :prevent_merge_without_jira_issue, type: Grape::API::Boolean, desc: 'Require an associated issue from Jira. Ultimate only.'
            optional :auto_duo_code_review_enabled, type: Grape::API::Boolean, desc: 'Enable automatic reviews by GitLab Duo on merge requests'
            optional :duo_code_review_decisions_enabled, type: Grape::API::Boolean, desc: 'Enable approval and change requests by GitLab Duo on merge requests. Behind a feature flag named `duo_code_review_decisions`, enabled by default.'
            optional :duo_code_review_depth_allowed, type: Grape::API::Boolean, desc: '[Beta] Allow Standard reviews by GitLab Duo Code Review Flow'
            optional :duo_code_review_default_depth, type: String, values: ::Gitlab::Duo::CodeReview::DEPTHS, desc: '[Beta] Default review depth for GitLab Duo Code Review Flow. One of `lite` or `standard`'
            optional :duo_remote_flows_enabled, type: Grape::API::Boolean, desc: 'Enable GitLab Duo remote flows for this project'
            optional :duo_sast_fp_detection_enabled, type: Grape::API::Boolean, desc: 'Enable GitLab Duo SAST false positive detection for this project'
            optional :duo_secret_detection_fp_enabled, type: Grape::API::Boolean, desc: 'Enable GitLab Duo Secret Detection false positive detection for this project'
            optional :duo_dependency_bump_breaking_changes_enabled, type: Grape::API::Boolean, desc: 'Turn on Agentic Breaking Change Resolution for this project'
            optional :duo_sast_vr_workflow_enabled, type: Grape::API::Boolean, desc: 'Enable GitLab Duo SAST vulnerability resolution workflow for this project. Requires the Security Manager, Maintainer, or Owner role.'
            optional :spp_repository_pipeline_access, type: Grape::API::Boolean, desc: 'Grant users and tokens read-only access to security policy configurations for enforcement in linked CI/CD projects. Ultimate only.'
            optional :merge_request_title_regex, type: String, desc: 'The regex the Merge Request must adhere to'
            optional :merge_request_title_regex_description, type: String, desc: 'The description for the regex the Merge Request must adhere to'
          end

          params :optional_filter_params_ee do
            optional :wiki_checksum_failed, type: Grape::API::Boolean, default: false, desc: 'If `true`, returns only projects whose wiki checksum calculation failed. Premium and Ultimate only.'
            optional :repository_checksum_failed, type: Grape::API::Boolean, default: false, desc: 'If `true`, returns only projects whose repository checksum calculation failed. Premium and Ultimate only.'
            optional :include_hidden, type: Grape::API::Boolean, default: false, desc: 'If `true`, includes hidden projects. Administrators only. Premium and Ultimate only.'
          end

          params :optional_update_params_ee do
            optional :allow_pipeline_trigger_approve_deployment, type: Grape::API::Boolean, desc: 'Allow pipeline triggerer to approve deployments. Premium and Ultimate only.'
            optional :mirror_user_id, type: Integer, desc: '[Deprecated] User responsible for all the activity surrounding a pull mirror event. Can only be set by admins. Premium and Ultimate only.'
            optional :only_mirror_protected_branches, type: Grape::API::Boolean, desc: '[Deprecated] Only mirror protected branches. Premium and Ultimate only.'
            optional :mirror_branch_regex, type: String, desc: '[Deprecated] Only mirror branches match regex'
            mutually_exclusive :only_mirror_protected_branches, :mirror_branch_regex
            optional :mirror_overwrites_diverged_branches, type: Grape::API::Boolean, desc: '[Deprecated] Pull mirror overwrites diverged branches. Premium and Ultimate only.'
            optional :import_url, type: String, desc: 'URL from which the project is imported'
            optional :fallback_approvals_required, type: Integer, desc: 'Overall approvals required when no rule is present'
            optional :issues_template, type: String, desc: 'Default description for Issues. Description is parsed with GitLab Flavored Markdown. Premium and Ultimate only.'
            optional :merge_requests_template, type: String, desc: 'Default description for merge requests. Description is parsed with GitLab Flavored Markdown. Premium and Ultimate only.'
            optional :merge_pipelines_enabled, type: Grape::API::Boolean, desc: 'Enable merged results pipelines.'
            optional :merge_trains_enabled, type: Grape::API::Boolean, desc: 'Enable merge trains.'
            optional :merge_trains_skip_train_allowed, type: Grape::API::Boolean, desc: 'Allow merge train merge requests to be merged without waiting for pipelines to finish.'
            optional :merge_train_enforcement, type: String, values: %w[allow_bypass enforce_for_all_users enforce_with_owner_override], desc: 'Merge train enforcement level. One of `allow_bypass`, `enforce_for_all_users`, or `enforce_with_owner_override`. Has no effect unless merge trains are enabled for the project. [Introduced](https://gitlab.com/gitlab-org/gitlab/-/issues/597962) in GitLab 19.2.'
            optional :max_pipelines_per_merge_train, type: Integer, desc: 'Maximum number of parallel pipelines per merge train for this project.'
            optional :ci_restrict_pipeline_cancellation_role, type: String, desc: 'Roles allowed to cancel pipelines and jobs. One of `developer`, `maintainer`, or `no_one`. Premium and Ultimate only.'
            optional :web_based_commit_signing_enabled,
              type: ::Grape::API::Boolean,
              desc: 'Enable web based commit signing for commits created from the GitLab UI. GitLab.com only.'
            optional :duo_remote_flows_enabled, type: Grape::API::Boolean, desc: 'Enable GitLab Duo remote flows for this project'
            optional :duo_sast_fp_detection_enabled, type: Grape::API::Boolean, desc: 'Enable GitLab Duo SAST false positive detection for this project. Requires the Maintainer or Owner role, or the Security Manager role behind a feature flag named `update_false_positive_detection_setting_permission`, disabled by default.'
            optional :duo_secret_detection_fp_enabled, type: Grape::API::Boolean, desc: 'Enable GitLab Duo Secret Detection false positive detection for this project. Requires the Maintainer or Owner role, or the Security Manager role behind a feature flag named `update_false_positive_detection_setting_permission`, disabled by default.'
            optional :duo_dependency_bump_breaking_changes_enabled, type: Grape::API::Boolean, desc: 'Enable Agentic Breaking Change Resolution for this project'
            optional :duo_sast_vr_workflow_enabled, type: Grape::API::Boolean, desc: 'Enable GitLab Duo SAST vulnerability resolution workflow for this project. Requires the Security Manager, Maintainer, or Owner role.'
            optional :spp_repository_pipeline_access, type: Grape::API::Boolean, desc: 'Grant users and tokens read-only access to security policy configurations for enforcement in linked CI/CD projects. Ultimate only.'
            optional :security_policy_pipeline_must_succeed, type: Grape::API::Boolean, desc: 'Require all security policy pipelines to succeed before merge requests can be merged'
            optional :reviewer_assignment_strategy, type: String, values: %w[disabled code_owners], desc: 'Strategy used to automatically assign reviewers to merge requests. One of `disabled` or `code_owners`. Responses can also return `dap_powered` for projects configured before GitLab 19.4. Premium and Ultimate only. [Introduced](https://gitlab.com/gitlab-org/gitlab/-/issues/601621) in GitLab 19.2.'
          end

          params :share_project_params_ee do
            optional :member_role_id, type: Integer, desc: 'ID of the member role to assign to the group.'
          end
        end

        class_methods do
          # We don't use "override" here as this module is included into various
          # API classes, and for reasons unknown the override would be verified
          # in the context of the including class, and not in the context of
          # `API::Helpers::ProjectsHelpers`.
          #
          # Likely this is related to
          # https://gitlab.com/gitlab-org/gitlab-foss/issues/50911.
          def create_project_mcp_params
            super + [:template_project_id, :use_custom_template, :group_with_project_templates_id]
          end

          def update_params_at_least_one_of
            super.concat [
              :auto_duo_code_review_enabled,
              :duo_code_review_decisions_enabled,
              :duo_code_review_depth_allowed,
              :duo_code_review_default_depth,
              :duo_remote_flows_enabled,
              :duo_sast_fp_detection_enabled,
              :duo_secret_detection_fp_enabled,
              :duo_dependency_bump_breaking_changes_enabled,
              :duo_sast_vr_workflow_enabled,
              :allow_pipeline_trigger_approve_deployment,
              :only_allow_merge_if_all_status_checks_passed,
              :approvals_before_merge,
              :external_authorization_classification_label,
              :fallback_approvals_required,
              :import_url,
              :issues_template,
              :mirror,
              :mirror_trigger_builds,
              :mirror_user_id,
              :only_mirror_protected_branches,
              :mirror_branch_regex,
              :mirror_overwrites_diverged_branches,
              :merge_requests_template,
              :merge_pipelines_enabled,
              :merge_trains_enabled,
              :merge_trains_skip_train_allowed,
              :merge_train_enforcement,
              :max_pipelines_per_merge_train,
              :requirements_access_level,
              :prevent_merge_without_jira_issue,
              :ci_restrict_pipeline_cancellation_role,
              :web_based_commit_signing_enabled,
              :spp_repository_pipeline_access,
              :security_policy_pipeline_must_succeed,
              :merge_request_title_regex,
              :merge_request_title_regex_description,
              :reviewer_assignment_strategy
            ]
          end
        end

        override :filter_attributes_using_license!
        def filter_attributes_using_license!(attrs)
          super

          unless ::License.feature_available?(:external_authorization_service_api_management)
            attrs.delete(:external_authorization_classification_label)
          end

          unless ::License.feature_available?(:protected_environments)
            attrs.delete(:allow_pipeline_trigger_approve_deployment)
          end

          unless ::License.feature_available?(:jira_issue_association_enforcement)
            attrs.delete(:prevent_merge_without_jira_issue)
          end

          unless ::License.feature_available?(:ci_pipeline_cancellation_restrictions)
            attrs.delete(:ci_restrict_pipeline_cancellation_role)
          end

          if params[:id].present?
            # Existing project (update) - check both license and availability
            unless ::License.feature_available?(:review_merge_request) &&
                ::Gitlab::Duo::CodeReview.automatic_review_available?(user_project)
              attrs.delete(:auto_duo_code_review_enabled)
            end
          else
            # New project (creation) - only check license
            attrs.delete(:auto_duo_code_review_enabled) unless ::License.feature_available?(:review_merge_request)
          end

          filter_duo_code_review_decision_attributes!(attrs)
          filter_duo_code_review_depth_attributes!(attrs)

          attrs.delete(:duo_remote_flows_enabled) unless License.feature_available?(:ai_workflows)

          # Edit-only: reviewer auto-assignment is configured against an existing
          # project, and reviewer_auto_assignment_available? gates on the
          # code_owners licensed feature.
          unless params[:id].present? && user_project.reviewer_auto_assignment_available?
            attrs.delete(:reviewer_assignment_strategy)
          end

          unless ::License.feature_available?(:merge_request_title_regex_check)
            attrs.delete(:merge_request_title_regex)
            attrs.delete(:merge_request_title_regex_description)
          end

          filter_duo_vulnerability_attributes!(attrs)
          filter_security_orchestration_policy_attributes!(attrs)
        end

        def filter_duo_code_review_decision_attributes!(attrs)
          return if params[:id].present? &&
            ::License.feature_available?(:review_merge_request) &&
            ::Gitlab::Duo::CodeReview.decisions_settings_available?(user_project)

          attrs.delete(:duo_code_review_decisions_enabled)
        end

        def filter_duo_code_review_depth_attributes!(attrs)
          return if params[:id].present? && ::Gitlab::Duo::CodeReview.depth_settings_available?(user_project)

          attrs.delete(:duo_code_review_depth_allowed)
          attrs.delete(:duo_code_review_default_depth)
        end

        def filter_security_orchestration_policy_attributes!(attrs)
          unless ::License.feature_available?(:security_orchestration_policies)
            attrs.delete(:spp_repository_pipeline_access)
            attrs.delete(:security_policy_pipeline_must_succeed)
            return
          end

          return if params[:id].present? && ::Feature.enabled?(:security_policy_pipeline_check, user_project)

          attrs.delete(:security_policy_pipeline_must_succeed)
        end

        def restrict_attrs_for_sec_ai_workflow_setting!(project, attrs)
          # rubocop:disable Gitlab/Authz/PermissionCheck -- admin_project is the pre-FF gate we're preserving
          return if can?(current_user, :admin_project, project)
          # rubocop:enable Gitlab/Authz/PermissionCheck

          return unless can?(current_user, :update_sec_ai_workflow_settings, project)

          allowed = [:duo_sast_vr_workflow_enabled, :duo_sast_fp_detection_enabled, :duo_secret_detection_fp_enabled]

          # rubocop:disable Gitlab/FeatureFlagKeyDynamic -- iterating over a fixed constant of setting-to-flag mappings

          EE::Projects::UpdateService::AI_WORKFLOW_SETTING_FEATURE_FLAGS.each do |attribute, feature_flag|
            allowed.delete(attribute) unless ::Feature.enabled?(feature_flag, project)
          end
          # rubocop:enable Gitlab/FeatureFlagKeyDynamic

          attrs.slice!(*allowed)
        end

        def filter_duo_vulnerability_attributes!(attrs)
          unless params[:id].present? && License.feature_available?(:ai_features)
            attrs.delete(:duo_sast_fp_detection_enabled)
            attrs.delete(:duo_sast_vr_workflow_enabled)
            attrs.delete(:duo_secret_detection_fp_enabled)
            attrs.delete(:duo_dependency_bump_breaking_changes_enabled)
            return
          end

          return if ::Feature.enabled?(:duo_secret_detection_false_positive, user_project)

          attrs.delete(:duo_secret_detection_fp_enabled)
        end
      end
    end
  end
end
