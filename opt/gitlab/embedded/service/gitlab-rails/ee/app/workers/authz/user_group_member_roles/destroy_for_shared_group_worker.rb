# frozen_string_literal: true

module Authz
  module UserGroupMemberRoles
    class DestroyForSharedGroupWorker
      include ApplicationWorker

      urgency :high
      data_consistency :sticky
      deduplicate :until_executed, if_deduplicated: :reschedule_once, including_scheduled: true
      idempotent!

      feature_category :permissions

      def perform(shared_group_id, shared_with_group_id)
        shared_group = ::Group.find_by_id(shared_group_id)
        shared_with_group = ::Group.find_by_id(shared_with_group_id)

        return unless shared_group && shared_with_group

        DestroyForSharedGroupService.new(shared_group, shared_with_group).execute
      end
    end
  end
end
