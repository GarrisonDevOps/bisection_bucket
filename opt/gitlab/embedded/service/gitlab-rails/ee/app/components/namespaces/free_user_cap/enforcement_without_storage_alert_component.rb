# frozen_string_literal: true

module Namespaces
  module FreeUserCap
    class EnforcementWithoutStorageAlertComponent < BaseAlertComponent
      extend ::Gitlab::Utils::Override

      include ::Gitlab::Utils::StrongMemoize
      include SafeFormatHelper

      PROMO_CODE = 'USER-LIMIT-19-2026'
      PROMO_PRICE = 19
      RETRIAL_COOLDOWN_DAYS = 90

      private

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
      strong_memoize_attr :trial_duration

      def retrial_window_days
        trial_duration.to_i + RETRIAL_COOLDOWN_DAYS
      end

      def alert_attributes
        {
          title: alert_title,
          body: alert_body,
          primary_cta: namespace_primary_cta,
          secondary_cta: namespace_secondary_cta
        }
      end

      def alert_title
        safe_format(
          _("Your namespace %{namespace_name} has been placed in %{link_start}a read-only state%{link_end}"),
          tag_pair(read_only_namespaces_link, :link_start, :link_end),
          namespace_name: namespace.name
        )
      end

      def alert_body
        return promo_alert_body if show_promo_cta?

        safe_format(
          _("Your private namespace is over %{link_start}the %{free_limit} user limit%{link_end}. To remove " \
            "the read-only state, an Owner can reduce the number of users in the namespace to %{free_limit} or " \
            "fewer, make the namespace public, or upgrade to a paid tier. If you need more time, you can start " \
            "a free %{duration}-day Ultimate trial or re-trial (available %{retrial_window} days after your " \
            "last trial started) to get unlimited users. %{seat_usage_link_start}View your seat " \
            "usage%{seat_usage_link_end} to see who counts toward the limit across your namespace."),
          tag_pair(free_user_limit_link, :link_start, :link_end),
          tag_pair(seat_usage_link, :seat_usage_link_start, :seat_usage_link_end),
          free_limit: free_user_limit,
          retrial_window: retrial_window_days,
          duration: trial_duration
        )
      end

      def promo_alert_body
        safe_format(
          _("Your private namespace is over %{link_start}the %{free_limit} user limit%{link_end}. To remove " \
            "the read-only state, an Owner can upgrade to a paid tier. For a limited time, you can start " \
            "a Premium subscription for %{promo_price} per user per month instead of %{regular_price}. " \
            "Alternatively, reduce the number of users in the namespace to %{free_limit} or fewer, make " \
            "the namespace public, or start a free %{duration}-day Ultimate trial to give yourself more time. " \
            "%{seat_usage_link_start}View your seat usage%{seat_usage_link_end} to see who counts toward " \
            "the limit across your namespace."),
          tag_pair(free_user_limit_link, :link_start, :link_end),
          tag_pair(seat_usage_link, :seat_usage_link_start, :seat_usage_link_end),
          free_limit: free_user_limit,
          promo_price: formatted_promo_price,
          regular_price: formatted_regular_price,
          duration: trial_duration
        )
      end

      def namespace_primary_cta
        return promo_primary_cta if show_promo_cta?

        render Pajamas::ButtonComponent.new(
          size: :small,
          variant: :confirm,
          href: group_billings_path(namespace, source: 'user-limit-alert-enforcement'),
          button_options: {
            class: 'gl-alert-action',
            data: {
              track_action: 'click_button',
              track_label: 'explore_paid_plans',
              track_property: tracking_property,
              testid: 'enforcement-without-storage-user-limit-primary-cta'
            }
          }
        ) do
          _('Explore paid plans or re-trial')
        end
      end

      def show_promo_cta?
        promo_cta_enabled? && premium_plan.present?
      end

      def promo_cta_enabled?
        Feature.enabled?(:free_user_cap_enforcement_promo_cta, namespace)
      end

      def promo_primary_cta
        render Pajamas::ButtonComponent.new(
          size: :small,
          variant: :confirm,
          href: promo_checkout_url,
          button_options: {
            class: 'gl-alert-action',
            data: {
              track_action: 'click_button',
              track_label: 'buy_now',
              track_property: tracking_property,
              testid: 'enforcement-without-storage-user-limit-primary-cta'
            }
          }
        ) do
          safe_format(_('Buy now at %{price} per user/month'), price: formatted_promo_price)
        end
      end

      def formatted_promo_price
        helpers.number_to_plan_currency(PROMO_PRICE)
      end

      def formatted_regular_price
        helpers.number_to_plan_currency(premium_plan.price_per_month)
      end

      def promo_checkout_url
        ::GitlabSubscriptions::PurchaseUrlBuilder
          .new(plan_id: premium_plan.id, namespace: namespace)
          .build(promo_code: PROMO_CODE)
      end

      def premium_plan
        plans_data&.find { |plan| plan.code == ::GitlabSubscriptions::SystemDefined::Plan::PREMIUM }
      end

      def plans_data
        ::GitlabSubscriptions::FetchSubscriptionPlansService.new(
          plan: namespace.plan_name_for_upgrading,
          namespace_id: namespace.id
        ).execute
      end
      strong_memoize_attr :plans_data

      def namespace_secondary_cta
        tag.div(class: 'js-hand-raise-lead-trigger', data: hand_raise_lead_data)
      end

      def hand_raise_lead_data
        {
          glm_content: 'enforcement-user-limit',
          button_text: _('Contact sales'),
          button_attributes: {
            category: 'secondary',
            size: 'small',
            class: 'gl-alert-action',
            'data-testid': 'enforcement-without-storage-user-limit-secondary-cta'
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
          testid: 'enforcement-without-storage-user-limit-alert'
        }
      end

      override :tracking_property
      def tracking_property
        'enforcement_without_storage_user_limit_banner'
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

      def free_user_limit_url
        help_page_path('user/free_user_limit.md')
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

      def read_only_namespaces_url
        help_page_path('user/read_only_namespaces.md', anchor: 'read-only-namespaces')
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
    end
  end
end
