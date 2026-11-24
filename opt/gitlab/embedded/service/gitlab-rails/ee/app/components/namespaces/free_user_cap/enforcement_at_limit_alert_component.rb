# frozen_string_literal: true

module Namespaces
  module FreeUserCap
    class EnforcementAtLimitAlertComponent < BaseAlertComponent
      extend ::Gitlab::Utils::Override

      private

      ENFORCEMENT_AT_LIMIT_ALERT = 'enforcement_at_limit_alert'

      def breached_cap_limit?
        ::Namespaces::FreeUserCap::Enforcement.new(namespace).at_limit?
      end

      def trial_duration
        ::GitlabSubscriptions::TrialDurationService.new.execute
      end

      def feature_name
        ENFORCEMENT_AT_LIMIT_ALERT
      end

      def alert_attributes
        {
          # see issue with ViewComponent overriding Kernel version
          # https://github.com/github/view_component/issues/156#issuecomment-737469885
          title: Kernel.format(
            s_(
              "EnforcementAtLimitAlert|Your top-level group %{namespace_name} has reached the %{free_limit} user limit"
            ),
            free_limit: free_user_limit,
            namespace_name: namespace.name
          ).html_safe,
          body: Kernel.format(
            s_("EnforcementAtLimitAlert|To invite more users, you can reduce the number of users in your " \
              "top-level group to %{pluralized_limit} or less. You can also upgrade to " \
              "a paid tier which do not have user limits. If you need additional " \
              "time, you can start a free %{duration}-day trial which includes unlimited users."),
            pluralized_limit: n_('%d user', '%d users', free_user_limit) % free_user_limit,
            link_end: link_end,
            duration: trial_duration
          ).html_safe,
          primary_cta: namespace_primary_cta,
          secondary_cta: namespace_secondary_cta
        }
      end

      override :tracking_property
      def tracking_property
        'enforcement_at_limit_user_limit_banner'
      end
    end
  end
end
