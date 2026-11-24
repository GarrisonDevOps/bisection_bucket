# frozen_string_literal: true

module Namespaces
  module Storage
    class BaseAlertComponent < ViewComponent::Base
      include ::Namespaces::StorageHelper
      include SafeFormatHelper

      DEFAULT_USAGE_THRESHOLDS = {
        none: 0,
        warning: 0.75,
        alert: 0.95,
        error: 1
      }.freeze

      # @param [Namespace, Group or Project] context
      # @param [User] user
      def initialize(context:, user:)
        @context = context
        @root_namespace = context.root_ancestor
        @user = user
        @root_storage_size = root_namespace.root_storage_size
      end

      private

      delegate :usage_quotas_path, :buy_storage_path, :link_button_to, to: :helpers
      attr_reader :context, :root_namespace, :user, :root_storage_size

      def render?
        return false unless user.present?
        return false unless user_has_access?
        return false unless root_storage_size.enforce_limit?
        return false if alert_level == :none
        return false if user_has_dismissed_alert?

        true
      end

      def alert_title
        return usage_percentage_alert_title unless root_storage_size.above_size_limit?

        if namespace_has_additional_storage_purchased?
          usage_percentage_alert_title
        else
          free_tier_alert_title
        end
      end

      def alert_message
        [
          alert_message_explanation << " " << alert_message_cta
        ]
      end

      def storage_docs_link
        help_page_path('user/storage_usage_quotas.md')
      end

      def usage_ratio
        root_storage_size.usage_ratio
      end

      def alert_level
        current_level = usage_thresholds.each_key.first

        usage_thresholds.each do |level, threshold|
          current_level = level if usage_ratio >= threshold
        end

        current_level
      end

      def user_has_dismissed_alert?
        if root_namespace.user_namespace?
          user.dismissed_callout?(feature_name: callout_feature_name)
        else
          user.dismissed_callout_for_group?(
            feature_name: callout_feature_name,
            group: root_namespace
          )
        end
      end

      def alert_callout_path
        root_namespace.user_namespace? ? callouts_path : group_callouts_path
      end

      def callout_feature_name
        "#{root_storage_size.enforcement_type}_alert_#{alert_level}_threshold"
      end

      def usage_thresholds
        DEFAULT_USAGE_THRESHOLDS
      end

      def dismissible?
        !attention_required_alert_level?
      end

      def alert_variant
        return :danger if attention_required_alert_level?

        alert_level
      end

      def attention_required_alert_level?
        [:alert, :error].include?(alert_level)
      end

      def user_has_access?
        # Requires admin_namespace only for users accessing Personal Namespaces
        if !context.is_a?(Project) && context.user_namespace?
          Ability.allowed?(user, :admin_namespace, context)
        else
          Ability.allowed?(user, :read_limit_alert, context)
        end
      end

      def show_purchase_link?
        return false unless ::Gitlab::CurrentSettings.automatic_purchased_storage_allocation?

        Ability.allowed?(user, :admin_namespace, root_namespace)
      end

      def namespace_has_additional_storage_purchased?
        root_namespace.additional_purchased_storage_size > 0
      end

      def purchase_link
        return unless show_purchase_link?

        buy_storage_path(root_namespace)
      end

      def usage_quotas_link
        return unless Ability.allowed?(user, :admin_namespace, root_namespace)

        usage_quotas_path(root_namespace, anchor: 'storage-quota-tab')
      end

      def formatted(number)
        number_to_human_size(number, delimiter: ',', precision: 2)
      end
    end
  end
end
