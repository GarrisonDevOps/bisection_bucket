# frozen_string_literal: true

module Namespaces
  module FreeUserCap
    class GroupOverLimitNotificationWorker
      include ApplicationWorker

      feature_category :user_management
      data_consistency :delayed
      idempotent!

      def perform(group_id, member_ids)
        return unless ::Namespaces::FreeUserCap.dashboard_limit_enabled?

        @group = Group.find_by_id(group_id)
        return unless @group.present? # could have been deleted by the time this runs

        top_level_groups.each do |top_level_group|
          next unless ::Namespaces::FreeUserCap::Enforcement.new(top_level_group).over_from_adding_users?(member_ids)

          NotifyOverLimitService.execute(top_level_group)
        end
      end

      private

      TOP_LEVEL_GROUPS_LIMIT = 10

      def top_level_groups
        # To protect our performance in this edge case feature, we'll limit the number of top level groups
        # we analyze.
        (@group.shared_groups + @group.shared_projects).map(&:root_ancestor).uniq.reject do |top_level_group|
          # ignore self as we'll already be notified of this in the UI and by default
          # inviting groups from inside our own hierarchy can not change user count
          @group.root_ancestor == top_level_group
        end.first(TOP_LEVEL_GROUPS_LIMIT)
      end
    end
  end
end
