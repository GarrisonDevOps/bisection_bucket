# frozen_string_literal: true

module EE
  module Projects
    module UpdateService
      include ::Gitlab::Utils::StrongMemoize

      extend ::Gitlab::Utils::Override

      DEFAULT_BRANCH_CHANGE_AUDIT_TYPE = 'project_default_branch_updated'
      DEFAULT_BRANCH_CHANGE_AUDIT_MESSAGE = "Default branch changed from %s to %s"
      PROJECT_TOPIC_CHANGE_AUDIT_TYPE = 'project_topics_updated'

      AI_WORKFLOW_SETTING_FEATURE_FLAGS = {
        duo_sast_vr_workflow_enabled: :update_sast_vr_setting_permission,
        duo_sast_fp_detection_enabled: :update_false_positive_detection_setting_permission,
        duo_secret_detection_fp_enabled: :update_false_positive_detection_setting_permission
      }.freeze

      AI_WORKFLOW_SETTINGS_ALWAYS_ALLOWED = %i[
        duo_vulnerability_context_analysis_enabled
      ].freeze

      PULL_MIRROR_ATTRIBUTES = %i[
        mirror
        mirror_user_id
        import_url
        username_only_import_url
        mirror_trigger_builds
        only_mirror_protected_branches
        mirror_overwrites_diverged_branches
        import_data_attributes
        mirror_branch_regex
      ].freeze

      override :validate!
      def validate!
        validate_repository_mirror_update
        # Must be before super because validate_default_branch_change calls change_head, which mutates the repo.
        validate_settings_policies

        super
      end

      override :execute
      def execute
        # Consume the reserved param up front so it can never reach attribute assignment.
        strip_settings_gate_param

        wiki_was_enabled = project.wiki_enabled?

        shared_runners_setting
        mirror_user_setting
        mirror_branch_setting
        track_duo_dependency_bump_breaking_changes_enabled_by

        return update_failed! if project.errors.any?

        if params[:project_setting_attributes].present? && !project.suggested_reviewers_available?
          params[:project_setting_attributes].delete(:suggested_reviewers_enabled)
        end

        prepare_analytics_dashboards_params!

        validate_web_based_commit_signing_enabled

        result = super do
          assign_repository_size_limit
        end

        attach_govern_warnings(result)

        if result[:status] == :success
          refresh_merge_trains(project)

          log_audit_events

          sync_wiki_on_enable if !wiki_was_enabled && project.wiki_enabled?
          project.import_state.force_import_job! if params[:mirror].present? && project.mirror?
          project.remove_import_data if project.previous_changes.include?('mirror') && !project.mirror?
          update_amazon_q_service_account!
          update_duo_workflow_service_account!
        end

        result
      end

      private

      # Memoized before mirror_user_setting injects mirror_user_id, so that injected
      # key is not treated as a requested mirror change by validate_repository_mirror_update.
      def pull_mirror_params_requested?
        PULL_MIRROR_ATTRIBUTES.any? { |attr| params.key?(attr) }
      end
      strong_memoize_attr :pull_mirror_params_requested?

      def validate_repository_mirror_update
        return unless pull_mirror_params_requested?
        return if disabling_mirror_without_new_import_url?
        return unless ::Import::Sync::Projects::WritePolicy.repository_mirroring_blocked?(project)

        raise_validation_error(
          s_('GithubUpdatesMirror|Stop GitHub updates before adding a repository mirror.')
        )
      end

      def disabling_mirror_without_new_import_url?
        params.key?(:mirror) && ::Gitlab::Utils.to_boolean(params[:mirror]) == false && !params.key?(:import_url)
      end

      def validate_settings_policies
        return unless settings_change_verdict.refused?

        # Some callers report only model errors, not the result message.
        project.errors.add(:base, settings_change_verdict.refusal_message)
        raise_validation_error(settings_change_verdict.refusal_message)
      end

      def settings_change_verdict
        return ::Govern::PolicyEngine::SettingsChangeGate::PASS if skip_settings_gate?

        ::Govern::PolicyEngine::SettingsChangeGate
          .for_project(project: project, actor: current_user, params: params)
          .execute
      end
      strong_memoize_attr :settings_change_verdict

      # The engine's own write-back skips the gate, so writes do not cascade.
      def strip_settings_gate_param
        params.delete(:skip_govern_settings_gate).present?
      end
      strong_memoize_attr :strip_settings_gate_param

      def skip_settings_gate?
        strip_settings_gate_param
      end

      def attach_govern_warnings(result)
        return if result[:status] != :success

        warnings = settings_change_verdict.warnings
        return if warnings.empty?

        # rubocop:disable Rails/Pluck -- plain array of hashes
        result[::Govern::PolicyEngine::SettingsChangeGate::WARNINGS_RESULT_KEY] =
          warnings.map { |warning| warning[:message] }
        # rubocop:enable Rails/Pluck
      end

      def assign_repository_size_limit
        limit = params.delete(:repository_size_limit)
        return unless limit

        # Repository size limit comes as MB from the view
        project.repository_size_limit = ::Gitlab::Utils.try_megabytes_to_bytes(limit)
      end

      def validate_web_based_commit_signing_enabled
        return unless params.key?(:web_based_commit_signing_enabled)

        return if ::Gitlab::Saas.feature_available?(:repositories_web_based_commit_signing) &&
          !namespace_settings_enabled?

        params.delete(:web_based_commit_signing_enabled)
      end

      def namespace_settings_enabled?
        project.group&.namespace_settings&.web_based_commit_signing_enabled
      end

      def prepare_analytics_dashboards_params!
        if params[:analytics_dashboards_pointer_attributes] &&
            params[:analytics_dashboards_pointer_attributes][:target_project_id].blank?

          params[:analytics_dashboards_pointer_attributes][:_destroy] = true
          params[:analytics_dashboards_pointer_attributes].delete(:target_project_id)
        end
      end

      override :remove_unallowed_params
      def remove_unallowed_params
        super

        unless project.licensed_feature_available?(:external_status_checks)
          params.delete(:only_allow_merge_if_all_status_checks_passed)
        end

        params.delete(:repository_size_limit) unless current_user&.can_admin_all_resources?

        remove_unauthorized_ai_workflow_settings
        remove_unauthorized_ai_audit_events_storage_setting
      end

      def remove_unauthorized_ai_audit_events_storage_setting
        setting_attrs = params[:project_setting_attributes]
        return unless setting_attrs.respond_to?(:key?)
        return unless setting_attrs.key?(:ai_audit_events_storage_enabled)

        return if can?(current_user, :update_storage_ai_audit_events, project)

        setting_attrs.delete(:ai_audit_events_storage_enabled)
      end

      def remove_unauthorized_ai_workflow_settings
        setting_attrs = params[:project_setting_attributes]
        return unless setting_attrs.respond_to?(:key?)
        return if can?(current_user, :update_duo_setting, project)

        is_sec_ai_manager = can?(current_user, :update_sec_ai_workflow_settings, project)

        # rubocop:disable Gitlab/FeatureFlagKeyDynamic -- iterating over a fixed constant of setting-to-flag mappings
        AI_WORKFLOW_SETTING_FEATURE_FLAGS.each do |attribute, feature_flag|
          next unless setting_attrs.key?(attribute)

          next if is_sec_ai_manager && ::Feature.enabled?(feature_flag, project)

          setting_attrs.delete(attribute)
        end
        # rubocop:enable Gitlab/FeatureFlagKeyDynamic

        return if is_sec_ai_manager

        AI_WORKFLOW_SETTINGS_ALWAYS_ALLOWED.each { |attribute| setting_attrs.delete(attribute) }
      end

      override :validate_default_branch_change
      def validate_default_branch_change
        if changing_default_branch? && default_branch_update_blocked_by_security_policy?
          raise_validation_error(s_("UpdateProject|Updating default branch is blocked by security policy"))
        end

        super
      end

      override :after_default_branch_change
      def after_default_branch_change(previous_default_branch)
        audit_context = {
          name: DEFAULT_BRANCH_CHANGE_AUDIT_TYPE,
          author: current_user,
          scope: project,
          target: project,
          message: format(DEFAULT_BRANCH_CHANGE_AUDIT_MESSAGE, previous_default_branch, project.default_branch),
          target_details: project.full_path,
          additional_details: {
            from: previous_default_branch,
            to: project.default_branch
          }
        }

        ::Gitlab::Audit::Auditor.audit(audit_context)
      end

      override :audit_topic_change
      def audit_topic_change(from:)
        # reload project topics without affecting shared project variable, as that leads to unwanted side effects
        # when publishing events
        to = ::Project.find(project.id).topic_list
        topics_changed = from != to

        return unless topics_changed

        ::Gitlab::Audit::Auditor.audit(
          name: PROJECT_TOPIC_CHANGE_AUDIT_TYPE,
          author: current_user,
          scope: project,
          target: project,
          message: "topics changed to: '#{to.join(',')}'",
          target_details: project.full_path,
          additional_details: {
            event_name: PROJECT_TOPIC_CHANGE_AUDIT_TYPE,
            from: from,
            to: to
          }
        )
      end

      def default_branch_update_blocked_by_security_policy?
        ::Security::SecurityOrchestrationPolicies::DefaultBranchUpdationCheckService.new(project: project).execute
      end

      # A user who enables shared runners must meet the credit card requirement if
      # there is one.
      def shared_runners_setting
        return unless params[:shared_runners_enabled]
        return if project.shared_runners_enabled
        return if user_can_enable_shared_runners?

        project.errors.add(:shared_runners_enabled, _('cannot be enabled until identity verification is completed'))
      end

      def user_can_enable_shared_runners?
        ::Users::IdentityVerification::AuthorizeCi.new(
          user: current_user,
          project: project
        ).user_can_enable_shared_runners?
      end

      # A user who changes any aspect of pull mirroring settings must be made
      # into the mirror user, to prevent them from acquiring capabilities
      # owned by the previous user, such as writing to a protected branch.
      #
      # Only admins can set the mirror user to be an arbitrary user.
      def mirror_user_setting
        return unless pull_mirror_params_requested? || mirror_ci_config_path_changed?

        if params[:mirror_user_id] && params[:mirror_user_id] != project.mirror_user_id
          project.errors.add(:mirror_user_id, 'is invalid') unless current_user&.admin?
        else
          params[:mirror_user_id] = current_user.id
        end
      end

      # Mirror pipelines build from this path as the mirror user. Reads the raw column so
      # reassignment still happens while mirroring is unavailable.
      def mirror_ci_config_path_changed?
        return false unless project[:mirror] && params.key?(:ci_config_path)

        params[:ci_config_path].presence != project.ci_config_path.presence
      end

      def mirror_branch_setting
        params[:only_mirror_protected_branches] = false if params[:mirror_branch_regex].present?
        params[:mirror_branch_regex] = nil if params[:only_mirror_protected_branches]
      end

      def track_duo_dependency_bump_breaking_changes_enabled_by
        new_value = duo_dependency_bump_breaking_changes_setting_param
        return if new_value.nil?

        if ::Gitlab::Utils.to_boolean(new_value)
          # No need to update enabled_by if value is unchanged
          return if project.duo_dependency_bump_breaking_changes_enabled

          project.project_setting.duo_dependency_bump_breaking_changes_enabled_by_id = current_user&.id
        else
          project.project_setting.duo_dependency_bump_breaking_changes_enabled_by_id = nil
        end
      end

      def duo_dependency_bump_breaking_changes_setting_param
        nested = params.dig(:project_setting_attributes, :duo_dependency_bump_breaking_changes_enabled)
        return nested unless nested.nil?

        params[:duo_dependency_bump_breaking_changes_enabled]
      end

      def log_audit_events
        ::Projects::ProjectChangesAuditor.new(current_user, project).execute
      end

      def sync_wiki_on_enable
        associated_wiki = project.wiki_repository
        return unless associated_wiki

        associated_wiki.repository.log_geo_updated_event
      end

      def refresh_merge_trains(project)
        return unless project.merge_pipelines_were_disabled?

        MergeTrains::Train.all_for_project(project).each(&:refresh_async)
      end

      def update_amazon_q_service_account!
        return unless duo_features_enabled_submitted? && ::Ai::AmazonQ.connected?

        amazon_q_service_account_user =
          ::Ai::Setting.for_organization_read_only(project.organization).amazon_q_service_account_user
        update_service_account(amazon_q_service_account_user)

        integration_params =
          if duo_features_effectively_enabled?
            { availability: 'default_on', auto_review_enabled: params[:amazon_q_auto_review_enabled] }
          else
            { availability: 'never_on', auto_review_enabled: false }
          end

        project.amazon_q_integration.update(integration_params.compact)
      end

      # GraphQL submits a boolean, so `false` must count as submitted.
      def duo_features_enabled_submitted?
        !params.dig(:project_setting_attributes, :duo_features_enabled).nil?
      end

      # The submitted value is not the truth once an ancestor lock applies; the saved setting resolves the lock,
      # so a resubmitted stale `true` under a never_on lock still removes access instead of granting it.
      def duo_features_effectively_enabled?
        project.duo_features_enabled
      end

      def update_duo_workflow_service_account!
        return unless ::Ai::DuoWorkflow.connected?

        duo_workflow_service_account_user =
          ::Ai::Setting.for_organization_read_only(project.organization).duo_workflow_service_account_user
        update_service_account(duo_workflow_service_account_user)
      end

      def update_service_account(service_account_user)
        return unless duo_features_enabled_submitted?

        service = if duo_features_effectively_enabled?
                    ::Ai::ServiceAccountMemberAddService.new(project, service_account_user)
                  else
                    ::Ai::ServiceAccountMemberRemoveService.new(current_user, project, service_account_user)
                  end

        service.execute
      end

      def non_assignable_project_params
        super + [:amazon_q_auto_review_enabled]
      end
    end
  end
end
