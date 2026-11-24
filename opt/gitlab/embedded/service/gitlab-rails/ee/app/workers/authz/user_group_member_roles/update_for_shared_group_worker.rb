# frozen_string_literal: true

module Authz
  module UserGroupMemberRoles
    class UpdateForSharedGroupWorker
      include ApplicationWorker

      urgency :high
      data_consistency :sticky
      deduplicate :until_executed, if_deduplicated: :reschedule_once, including_scheduled: true
      idempotent!

      feature_category :permissions

      def perform(group_group_link_id)
        link = GroupGroupLink.find_by_id(group_group_link_id)

        return unless link

        UpdateForSharedGroupService.new(link).execute
      end
    end
  end
end
