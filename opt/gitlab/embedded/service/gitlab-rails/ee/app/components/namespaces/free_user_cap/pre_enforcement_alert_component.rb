# frozen_string_literal: true

module Namespaces
  module FreeUserCap
    class PreEnforcementAlertComponent < BaseAlertComponent
      extend ::Gitlab::Utils::Override

      include SafeFormatHelper

      ENFORCEMENT_DATE = Date.new(2026, 8, 15)

      private

      def breached_cap_limit?
        return false unless ::Namespaces::FreeUserCap::PreEnforcement.new(namespace).qualifies?

        ::Namespaces::FreeUserCap::EnforcementWithoutStorage.new(namespace).over_limit?
      end

      def variant
        :warning
      end

      def dismissible
        false
      end

      def dismissed?
        false
      end

      def alert_attributes
        {
          title: alert_title,
          body: safe_format(
            _("Free top-level namespaces with private visibility cannot have more than %{free_limit} users. " \
              "From %{strong_start}%{enforcement_date}%{strong_end}, if your namespace has more than " \
              "%{free_limit} users, it will be placed in %{link_start}a read-only state%{link_end}. " \
              "To prevent this, reduce the number of users in the namespace, make the namespace " \
              "public, upgrade to a paid tier, or start a free %{duration}-day Ultimate trial. " \
              "%{seat_usage_link_start}View your seat usage%{seat_usage_link_end} to see who counts " \
              "toward the limit across your namespace."),
            tag_pair(tag.strong, :strong_start, :strong_end),
            tag_pair(read_only_namespaces_link, :link_start, :link_end),
            tag_pair(seat_usage_link, :seat_usage_link_start, :seat_usage_link_end),
            enforcement_date: l(ENFORCEMENT_DATE, format: :long),
            free_limit: free_user_limit,
            duration: trial_duration
          ),
          primary_cta: namespace_primary_cta,
          secondary_cta: namespace_secondary_cta
        }
      end

      def alert_title
        safe_format(
          _("Your namespace %{namespace_name} is over %{link_start}the %{free_limit} user limit%{link_end}"),
          tag_pair(free_user_limit_link, :link_start, :link_end),
          namespace_name: namespace.name,
          free_limit: free_user_limit
        )
      end

      def namespace_primary_cta
        render Pajamas::ButtonComponent.new(
          size: :small,
          variant: :confirm,
          href: group_billings_path(namespace, source: 'user-limit-alert-notification'),
          button_options: {
            class: 'gl-alert-action',
            data: {
              track_action: 'click_button',
              track_label: 'explore_paid_plans',
              track_property: tracking_property,
              testid: 'pre-enforcement-user-limit-primary-cta'
            }
          }
        ) do
          _('Explore paid plans')
        end
      end

      def namespace_secondary_cta
        tag.div(class: 'js-hand-raise-lead-trigger', data: hand_raise_lead_data)
      end

      def hand_raise_lead_data
        {
          glm_content: 'pre-enforcement-user-limit',
          button_text: _('Contact sales'),
          button_attributes: {
            category: 'secondary',
            size: 'small',
            class: 'gl-alert-action',
            'data-testid': 'pre-enforcement-user-limit-secondary-cta'
          }.to_json,
          cta_tracking: {
            action: 'click_button',
            label: 'contact_sales',
            property: tracking_property
          }.to_json
        }
      end

      def base_alert_data
        {
          track_action: 'render',
          track_property: tracking_property,
          testid: 'pre-enforcement-user-limit-alert'
        }
      end

      def trial_duration
        ::GitlabSubscriptions::TrialDurationService.new.execute
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

      def read_only_namespaces_link
        link_to(
          '',
          read_only_namespaces_url,
          target: '_blank',
          rel: 'noopener noreferrer',
          data: {
            track_action: 'click_link',
            track_label: 'read_only_namespaces',
            track_property: tracking_property
          }
        )
      end

      def seat_usage_link
        link_to(
          '',
          group_usage_quotas_path(namespace, anchor: 'seats-quota-tab'),
          data: {
            track_action: 'click_link',
            track_label: 'view_seat_usage',
            track_property: tracking_property
          }
        )
      end

      override :tracking_property
      def tracking_property
        'pre_enforcement_user_limit_banner'
      end

      def free_user_limit_url
        help_page_path('user/free_user_limit.md')
      end

      def read_only_namespaces_url
        help_page_path('user/read_only_namespaces.md', anchor: 'read-only-namespaces')
      end
    end
  end
end
