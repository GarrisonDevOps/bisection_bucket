# frozen_string_literal: true

module Namespaces
  module FreeUserCap
    class NonOwnerEnforcementWithoutStorageAlertComponent < EnforcementWithoutStorageAlertComponent
      extend ::Gitlab::Utils::Override

      private

      def render?
        return false unless ::Namespaces::FreeUserCap.non_owner_access?(user: user, namespace: namespace)

        breached_cap_limit?
      end

      override :tracking_property
      def tracking_property
        'non_owner_enforcement_without_storage_user_limit_banner'
      end

      def alert_attributes
        {
          title: alert_title,
          body: safe_format(
            _("Your private namespace is over %{link_start}the %{free_limit} user limit%{link_end}. Contact your " \
              "group Owner to reduce the number of users in the namespace, make the namespace public, or upgrade " \
              "to a paid tier."),
            tag_pair(free_user_limit_link, :link_start, :link_end),
            free_limit: free_user_limit
          )
        }
      end
    end
  end
end
