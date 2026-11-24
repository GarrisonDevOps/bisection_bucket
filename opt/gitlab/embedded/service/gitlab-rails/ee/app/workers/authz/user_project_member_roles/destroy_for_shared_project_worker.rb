# frozen_string_literal: true

module Authz
  module UserProjectMemberRoles
    class DestroyForSharedProjectWorker
      include ApplicationWorker

      urgency :high
      data_consistency :sticky
      deduplicate :until_executed, if_deduplicated: :reschedule_once, including_scheduled: true
      idempotent!

      feature_category :permissions

      def perform(project_id, group_id)
        shared_project = ::Project.find_by_id(project_id)
        shared_with_group = ::Group.find_by_id(group_id)

        return unless shared_project && shared_with_group

        DestroyForSharedProjectService.new(shared_project, shared_with_group).execute
      end
    end
  end
end
