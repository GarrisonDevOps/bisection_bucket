# frozen_string_literal: true

module Govern
  module PolicyEngine
    # Writes one catalog setting to a project through Projects::UpdateService,
    # so the usual validations, audit events, and save-time events still run.
    class ProjectSettingWriter
      # Projects::UpdateService has no param for this setting, so we write the security settings row directly.
      SECURITY_SETTING = 'secret_push_protection_enabled'

      def initialize(project:, actor:)
        @project = project
        @actor = actor
      end

      # @return [Hash] { status: :success }, or { status: :error, message: }.
      def write(setting, value)
        result = perform(setting, value)
        # Drop the unsaved attributes of a failed write so they cannot fail the next write.
        project.reset if result[:status] != :success

        result
      rescue StandardError => e
        ::Gitlab::ErrorTracking.track_and_raise_for_dev_exception(
          e, project_id: project.id, setting: setting
        )

        project.reset
        # The result may be surfaced or persisted, so the exception detail stays in error tracking.
        error("unexpected error while writing setting #{setting}")
      end

      private

      attr_reader :project, :actor

      def perform(setting, value)
        return write_security_setting(value) if setting == SECURITY_SETTING

        # The engine dispatches every write as the admin bot, and no granular
        # permission covers these settings yet, so assert the system actor.
        return error('actor is not the policy engine bot') unless actor&.admin_bot?

        return error('project or one of its ancestors is archived') if project.self_or_ancestors_archived?

        params = ProjectSettingParams.for(setting, value)
        return error("no write mapping for setting #{setting} with value #{value.inspect}") unless params

        Projects::UpdateService.new(project, actor, params.merge(skip_govern_settings_gate: true)).execute
      end

      # Applies the same guards and audit event as the REST endpoint for this
      # row (API::ProjectSecuritySettings).
      def write_security_setting(value)
        # Unlicensed projects never see this setting in their context, so this write can only be a mistake.
        return error('secret push protection is not licensed') unless
          project.licensed_feature_available?(:secret_push_protection)

        return error("#{SECURITY_SETTING} takes a boolean, got #{value.inspect}") unless
          [true, false].include?(value)

        return error('actor is not allowed to update the security setting') unless
          Ability.allowed?(actor, :update_security_setting, project)

        return error('project or one of its ancestors is archived') if project.self_or_ancestors_archived?

        if !value && ::Gitlab::CurrentSettings.secret_push_protection_enforced
          return error('secret push protection is enforced for all projects in the instance')
        end

        security = project.security_setting
        return error('project has no security settings row') unless security

        security.set_secret_push_protection!(enabled: value)
        audit_security_setting(value)
        { status: :success }
      end

      # The setting is already committed, so a failed audit must not fail the write.
      def audit_security_setting(value)
        ::Gitlab::Audit::Auditor.audit(
          name: 'project_security_setting_updated',
          author: actor,
          scope: project,
          target: project,
          message: "User #{actor.name} updated `#{SECURITY_SETTING}` to #{value}"
        )
      rescue StandardError => e
        ::Gitlab::ErrorTracking.track_exception(e, project_id: project.id)
      end

      def error(message)
        { status: :error, message: message }
      end
    end
  end
end
