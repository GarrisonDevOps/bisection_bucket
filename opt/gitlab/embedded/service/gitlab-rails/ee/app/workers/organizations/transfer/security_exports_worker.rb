# frozen_string_literal: true

module Organizations
  module Transfer
    class SecurityExportsWorker
      include ApplicationWorker

      data_consistency :sticky
      deduplicate :until_executed
      idempotent!
      feature_category :vulnerability_management
      urgency :low
      loggable_arguments 0, 1, 2

      defer_on_database_health_signal :gitlab_sec,
        [:dependency_list_export_parts, :vulnerability_export_parts],
        1.minute

      concurrency_limit -> { 1 }

      def perform(group_id, old_organization_id, new_organization_id)
        result = ::Organizations::Transfer::SecurityExportsService.new(
          group: ::Group.find_by_id(group_id),
          old_organization: ::Organizations::Organization.find_by_id(old_organization_id),
          new_organization: ::Organizations::Organization.find_by_id(new_organization_id)
        ).execute

        log_extra_metadata_on_done(:status, result.status)
        log_extra_metadata_on_done(:reason, result.reason) if result.error?
      end
    end
  end
end
