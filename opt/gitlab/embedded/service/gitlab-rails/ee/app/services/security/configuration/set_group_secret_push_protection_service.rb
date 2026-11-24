# frozen_string_literal: true

module Security
  module Configuration
    class SetGroupSecretPushProtectionService < SetProjectSecuritySettingBaseService
      private

      def subject_project_ids
        group_project_ids = all_project_ids
        @filtered_out_projects_ids += @excluded_projects_ids & group_project_ids
        group_project_ids - @filtered_out_projects_ids
      end

      def all_project_ids
        Gitlab::Database::NamespaceProjectIdsEachBatch.new(
          group_id: @subject.id
        ).execute
      end

      def audit
        return unless @subject.is_a?(Group)

        message = build_group_message(fetch_filtered_out_projects_full_path)

        audit_context = build_audit_context(
          name: 'group_secret_push_protection_updated',
          message: message
        )

        ::Gitlab::Audit::Auditor.audit(audit_context)
      end

      def setting_key
        :secret_push_protection_enabled
      end

      def fetch_filtered_out_projects_full_path
        return [] unless @filtered_out_projects_ids.present?

        Project.id_in(@filtered_out_projects_ids).select(:namespace_id, :path).map(&:full_path)
      end

      def build_group_message(filtered_out_projects_full_path)
        message = "Secret push protection has been #{@enable ? 'enabled' : 'disabled'} for group #{@subject.name} and \
all of its inherited groups/projects"

        unless filtered_out_projects_full_path.empty?
          message += " except for #{filtered_out_projects_full_path.join(', ')}"
        end

        message
      end

      def post_update(project_ids)
        return unless project_ids.present?

        Security::AnalyzersStatus::ScheduleSettingChangedUpdateWorker.perform_async(project_ids, "secret_detection")
      end
    end
  end
end
