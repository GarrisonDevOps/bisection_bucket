# frozen_string_literal: true

module Authz
  module UserGroupMemberRoles
    class DestroyForGroupWorker
      include ApplicationWorker

      urgency :high
      data_consistency :sticky
      deduplicate :until_executed, if_deduplicated: :reschedule_once, including_scheduled: true
      idempotent!

      feature_category :permissions

      def perform(user_id, group_id)
        user = ::User.find_by_id(user_id)
        group = ::Group.find_by_id(group_id)

        return unless user && group

        ::Authz::UserGroupMemberRoles::DestroyForGroupService
          .new(user, group).execute
      end
    end
  end
end
