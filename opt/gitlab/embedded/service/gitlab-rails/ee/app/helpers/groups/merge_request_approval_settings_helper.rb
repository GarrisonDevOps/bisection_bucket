# frozen_string_literal: true

module Groups
  module MergeRequestApprovalSettingsHelper
    def can_update_merge_request_approval_settings?(user, group)
      Ability.allowed?(user, :update_merge_request_approval_setting, group)
    end
  end
end
