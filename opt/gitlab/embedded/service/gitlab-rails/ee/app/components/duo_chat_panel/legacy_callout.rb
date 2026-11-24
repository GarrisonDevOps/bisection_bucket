# frozen_string_literal: true

# This implements the auto-expand behavior for panel states that used to leverage the legacy
# `duo_panel_empty_state_auto_expanded` callout.
# Those states have been merged back to the main panel component which relies on
# `duo_panel_auto_expanded`, but we still want to respect cases where users had dismissed the legacy
# panel, so we gate the auto-expand behavior behind the `duo_panel_empty_state_auto_expanded` callout.
module DuoChatPanel
  module LegacyCallout
    include DuoChatPanel::PanelAutoExpand

    private

    def auto_expanded?(user)
      return false unless user
      return false if user.dismissed_callout?(feature_name: 'duo_panel_empty_state_auto_expanded')

      should_auto_expand_panel?(user, 'duo_panel_auto_expanded')
    end
  end
end
