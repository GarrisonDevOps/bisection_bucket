# frozen_string_literal: true

module Ai
  module ToolRules
    # Single source of truth for the tool-rule permission values. Shared by the
    # ToolRule model enum, the tool-rule resolution domain, and the GraphQL
    # ToolPermissionEnum so the allow/ask/deny strings are defined in one place
    # instead of repeated as bare literals.
    module Permissions
      ALLOW = 'allow'
      ASK = 'ask'
      DENY = 'deny'

      ACCESS_TYPES = %i[web_access local_access background_access].freeze

      # Most restrictive wins: deny > ask > allow.
      RESTRICTIVENESS = { DENY => 2, ASK => 1, ALLOW => 0 }.freeze

      # A background flow has no human to answer an `ask`, so it becomes `allow`, or `deny` under
      # fail-closed. Enforcement and display both call this, so shown and enforced values match.
      #
      # @param permission [String] the tool's default permission
      # @param fail_closed [Boolean] whether the namespace opted into background fail-closed
      # @return [String] the permission a background flow applies
      def self.background_effective(permission, fail_closed: false)
        return permission unless permission.to_s == ASK

        fail_closed ? DENY : ALLOW
      end
    end
  end
end
