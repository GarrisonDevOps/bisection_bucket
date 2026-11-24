# frozen_string_literal: true

module Groups
  module Settings
    module GitlabDuo
      module ModelSelectionHelper
        def group_model_selection_view_model(group)
          {
            groupId: group.to_gid,
            modelSelectionAllowlistAvailable: group_model_selection_allowlist_available?(group),
            purchaseCreditsPath: subscription_portal_gitlab_com_purchase_credits_url(group.id)
          }
        end

        private

        def group_model_selection_allowlist_available?(group)
          can?(current_user, :read_model_selection_allowlist, group) &&
            can?(current_user, :update_model_selection_allowlist, group)
        end
      end
    end
  end
end
