# frozen_string_literal: true

module Groups
  class ResetSeatCalloutsWorker
    include ApplicationWorker

    data_consistency :delayed
    feature_category :seat_cost_management
    deduplicate :until_executed
    idempotent!

    # rubocop: disable CodeReuse/ActiveRecord -- GroupCallout scopes missing
    def perform(group_id)
      group = Group.find_by_id(group_id)
      return unless group

      owner_ids = group.owner_ids

      Users::GroupCallout.where(
        group: group,
        user_id: owner_ids,
        feature_name: feature_callouts
      ).delete_all
    end
    # rubocop: enable CodeReuse/ActiveRecord

    private

    def feature_callouts
      [EE::Users::GroupCalloutsHelper::ALL_SEATS_USED_ALERT]
    end
  end
end
