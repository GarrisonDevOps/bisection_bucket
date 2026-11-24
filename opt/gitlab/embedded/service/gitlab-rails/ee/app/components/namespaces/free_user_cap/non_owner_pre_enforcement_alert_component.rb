# frozen_string_literal: true

module Namespaces
  module FreeUserCap
    class NonOwnerPreEnforcementAlertComponent < PreEnforcementAlertComponent
      extend ::Gitlab::Utils::Override

      private

      def render?
        return false unless ::Namespaces::FreeUserCap.non_owner_access?(user: user, namespace: namespace)

        breached_cap_limit?
      end

      override :tracking_property
      def tracking_property
        'non_owner_pre_enforcement_user_limit_banner'
      end

      def alert_attributes
        {
          title: alert_title,
          body: safe_format(
            _("Free top-level namespaces with private visibility cannot have more than %{free_limit} users. " \
              "From %{strong_start}%{enforcement_date}%{strong_end}, if your namespace has more than " \
              "%{free_limit} users, it will be placed in %{link_start}a read-only state%{link_end}. " \
              "Contact your top-level group Owner to reduce the number of users in the namespace, make the namespace " \
              "public, upgrade to a paid tier, or start a free %{duration}-day Ultimate trial."),
            tag_pair(tag.strong, :strong_start, :strong_end),
            tag_pair(read_only_namespaces_link, :link_start, :link_end),
            enforcement_date: l(ENFORCEMENT_DATE, format: :long),
            free_limit: free_user_limit,
            duration: trial_duration
          )
        }
      end
    end
  end
end
