# frozen_string_literal: true

module Namespaces
  module FreeUserCap
    class NonOwnerEnforcementAlertComponent < EnforcementAlertComponent
      extend ::Gitlab::Utils::Override

      private

      def render?
        return false unless ::Namespaces::FreeUserCap.non_owner_access?(user: user, namespace: namespace)

        breached_cap_limit?
      end

      def alert_attributes
        {
          title: alert_title,
          body: safe_format(
            _("To remove the %{link_start}read-only%{link_end} state and regain write access, " \
              "ask your top-level group owner(s) to reduce the number of users in your top-level group to " \
              "%{free_limit} users or less, or to upgrade to a paid tier which do not have " \
              "user limits."),
            tag_pair(free_user_limit_link, :link_start, :link_end),
            free_limit: free_user_limit
          )
        }
      end

      override :tracking_property
      def tracking_property
        'non_owner_enforcement_user_limit_banner'
      end
    end
  end
end
