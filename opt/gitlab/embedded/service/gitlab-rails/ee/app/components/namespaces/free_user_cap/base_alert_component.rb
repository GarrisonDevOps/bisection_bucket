# frozen_string_literal: true

module Namespaces
  module FreeUserCap
    class BaseAlertComponent < ViewComponent::Base
      # @param [Namespace or Group] namespace
      # @param [User] user
      # @param [String, nil] content_class
      def initialize(namespace:, user:, content_class: nil)
        @namespace = namespace
        @user = user
        @content_class = content_class
      end

      private

      attr_reader :namespace, :user, :content_class

      def render?
        return false unless ::Namespaces::FreeUserCap.can_read_billable_members?(user: user, namespace: namespace)
        return false if dismissed?

        breached_cap_limit?
      end

      def breached_cap_limit?
        ::Namespaces::FreeUserCap::Enforcement.new(namespace).over_limit?
      end

      def variant
        :warning
      end

      def dismissible
        true
      end

      def dismissed?
        user.dismissed_callout_for_group?(feature_name: feature_name, group: namespace)
      end

      def alert_data
        return base_alert_data unless dismissible

        base_alert_data.merge(
          feature_id: feature_name,
          dismiss_endpoint: Rails.application.routes.url_helpers.group_callouts_path,
          group_id: namespace.id
        )
      end

      def base_alert_data
        {
          track_action: 'render',
          track_label: 'user_limit_banner',
          track_property: tracking_property,
          testid: 'user-over-limit-free-plan-alert'
        }
      end

      def close_button_data
        {
          track_action: 'dismiss_banner',
          track_label: 'user_limit_banner',
          track_property: tracking_property,
          testid: 'user-over-limit-free-plan-dismiss'
        }
      end

      def namespace_primary_cta
        render Pajamas::ButtonComponent.new(variant: :confirm, size: :small,
          href: group_usage_quotas_path(namespace),
          button_options: {
            class: 'gl-alert-action',
            data: {
              track_action: 'click_button',
              track_label: 'manage_members',
              track_property: tracking_property,
              testid: 'user-over-limit-primary-cta'
            }
          }
        ) do
          _('Manage members')
        end
      end

      def namespace_secondary_cta
        render Pajamas::ButtonComponent.new(size: :small,
          href: group_billings_path(namespace, source: 'user-limit-alert-enforcement'),
          button_options: {
            class: 'gl-alert-action',
            data: {
              track_action: 'click_button',
              track_label: 'explore_paid_plans',
              track_property: tracking_property,
              testid: 'user-over-limit-secondary-cta'
            }
          }
        ) do
          _('Explore paid plans')
        end
      end

      def tracking_property
        # The subclass extending this component should define the #tracking_property method to return
        # a distinct value used to differentiate this banner in Snowplow tracking.
        raise NotImplementedError, "#{self.class} should implement #{__method__}"
      end

      def link_end
        '</a>'.html_safe
      end

      def free_user_limit
        ::Namespaces::FreeUserCap.dashboard_limit
      end
    end
  end
end
