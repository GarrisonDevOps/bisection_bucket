# frozen_string_literal: true

module Authz
  module UserProjectMemberRoles
    class UpdateForSharedProjectWorker
      include ApplicationWorker

      urgency :high
      data_consistency :sticky
      deduplicate :until_executed, if_deduplicated: :reschedule_once, including_scheduled: true
      idempotent!

      feature_category :permissions

      def perform(project_group_link_id)
        link = ProjectGroupLink.find_by_id(project_group_link_id)

        return unless link

        UpdateForSharedProjectService.new(link).execute
      end
    end
  end
end
