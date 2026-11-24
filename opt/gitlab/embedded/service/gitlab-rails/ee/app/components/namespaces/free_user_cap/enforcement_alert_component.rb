# frozen_string_literal: true

module Namespaces
  module FreeUserCap
    class EnforcementAlertComponent < BaseAlertComponent
      extend ::Gitlab::Utils::Override

      private

      include SafeFormatHelper

      def variant
        :danger
      end

      def dismissible
        false
      end

      def dismissed?
        false
      end

      def trial_duration
        ::GitlabSubscriptions::TrialDurationService.new.execute
      end

      def alert_attributes
        {
          title: alert_title,
          body: safe_format(_("To remove the %{link_start}read-only%{link_end} state and regain write access, " \
                  "you can reduce the number of users in your top-level group to %{free_limit} users or " \
                  "less. You can also upgrade to a paid tier, which do not have user limits. If you " \
                  "need additional time, you can start a free %{duration}-day trial which includes unlimited " \
                  "users."),
            tag_pair(free_user_limit_link, :link_start, :link_end),
            free_limit: free_user_limit,
            duration: trial_duration),
          primary_cta: namespace_primary_cta,
          secondary_cta: namespace_secondary_cta
        }
      end

      def alert_title
        safe_format(_("Your top-level group %{namespace_name} is over the %{free_limit} user " \
          'limit and has been placed in a read-only state.'),
          free_limit: free_user_limit,
          namespace_name: namespace.name)
      end

      def free_user_limit_link
        link_to(
          '',
          free_user_limit_url,
          target: '_blank',
          rel: 'noopener noreferrer',
          data: {
            track_action: 'click_link',
            track_label: 'free_user_limit',
            track_property: tracking_property
          }
        )
      end

      override :tracking_property
      def tracking_property
        'enforcement_user_limit_banner'
      end

      def free_user_limit_url
        help_page_path('user/free_user_limit.md')
      end
    end
  end
end
