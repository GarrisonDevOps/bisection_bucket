# frozen_string_literal: true

module Security
  module Configuration
    class SetProjectSecuritySettingBaseService
      include ::Gitlab::ExclusiveLeaseHelpers

      PROJECTS_BATCH_SIZE = 100
      LEASE_TTL = 30.minutes
      LEASE_TRY_AFTER = 3.seconds

      def initialize(
        subject:, enable:, current_user:, excluded_projects_ids: [])
        @subject = subject
        @enable = enable
        @current_user = current_user
        @excluded_projects_ids = excluded_projects_ids || []
        @filtered_out_projects_ids = []
      end

      def execute
        return unless valid_request?

        updated_project_ids = []
        project_ids = subject_project_ids
        in_lock(lease_key, ttl: LEASE_TTL, sleep_sec: LEASE_TRY_AFTER) do
          project_ids.each_slice(PROJECTS_BATCH_SIZE) do |project_ids_batch|
            batch_updated_ids = update_security_setting(project_ids_batch)
            updated_project_ids.concat(batch_updated_ids)
          end
        end

        post_update(updated_project_ids)

        @enable
      ensure
        audit if updated_project_ids.present?
      end

      protected

      def lease_key
        "set_project_security_settings:#{@subject}"
      end

      def valid_request?
        @subject.present? && !@subject.self_or_ancestors_archived? && @current_user.present? &&
          [true, false].include?(@enable)
      end

      def update_security_setting(project_ids)
        # rubocop:disable CodeReuse/ActiveRecord -- Specific use-case for this service
        settings_to_update = ProjectSecuritySetting.for_projects(project_ids).where(setting_key => !@enable)
        updated_project_ids = settings_to_update.limit(PROJECTS_BATCH_SIZE).pluck(:project_id)
        # rubocop:enable CodeReuse/ActiveRecord

        settings_to_update.update_all(setting_key => @enable, updated_at: Time.current) if updated_project_ids.any?

        updated_project_ids + create_missing_security_setting(project_ids)
      end

      def create_missing_security_setting(project_ids)
        projects_without_security_setting = Project.id_in(project_ids).without_security_setting
        return [] unless projects_without_security_setting.any?

        project_ids_to_create = []
        security_setting_attributes = projects_without_security_setting.map do |project|
          project_id = project.id
          project_ids_to_create << project_id
          {
            project_id: project_id,
            setting_key => @enable,
            updated_at: Time.current
          }
        end

        ProjectSecuritySetting.upsert_all(security_setting_attributes)
        project_ids_to_create
      end

      def build_audit_context(name:, message:)
        {
          name: name,
          author: @current_user,
          scope: @subject,
          target: @subject,
          message: message
        }
      end

      def post_update(project_ids)
        # No-op by default
      end

      def audit
        raise NotImplementedError
      end

      def subject_project_ids
        raise NotImplementedError
      end

      def setting_key
        raise NotImplementedError
      end
    end
  end
end
