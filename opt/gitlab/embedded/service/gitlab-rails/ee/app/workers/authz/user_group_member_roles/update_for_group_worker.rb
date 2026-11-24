# frozen_string_literal: true

module Authz
  module UserGroupMemberRoles
    class UpdateForGroupWorker
      include ApplicationWorker

      urgency :high
      data_consistency :sticky
      deduplicate :until_executed, if_deduplicated: :reschedule_once, including_scheduled: true
      idempotent!

      feature_category :permissions

      def perform(member_id)
        member = Member.find_by_id(member_id)

        return unless member

        UpdateForGroupService.new(member).execute
      end
    end
  end
end
