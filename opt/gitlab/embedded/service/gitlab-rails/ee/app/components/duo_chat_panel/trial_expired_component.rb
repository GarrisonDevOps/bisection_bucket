# frozen_string_literal: true

module DuoChatPanel
  class TrialExpiredComponent < ViewComponent::Base
    include DuoChatPanel::PanelCommon
    include DuoChatPanel::LegacyCallout

    def initialize(container:, user:)
      @user = user
      @strategy = saas? ? GitlabComStrategy.new(container.record, user) : SelfManagedStrategy.new(user)
    end

    private

    attr_reader :user, :strategy

    def data
      {
        testid: 'duo-chat-panel-trial-expired',
        is_trial_expired: 'true',
        buy_addon_path: (strategy.expired_buy_path if strategy.can_buy_addon?),
        can_buy_addon: strategy.can_buy_addon?.to_s,
        can_start_trial: 'false',
        auto_expand: auto_expanded?(user).to_s
      }.compact
    end

    class GitlabComStrategy
      def initialize(source, user)
        @source = source
        @user = user
      end

      def can_buy_addon?
        root_namespace.present? && Ability.allowed?(@user, :edit_billing, root_namespace)
      end

      def expired_buy_path
        plans_data = ::GitlabSubscriptions::FetchSubscriptionPlansService.new(
          plan: root_namespace.plan_name_for_upgrading,
          namespace_id: root_namespace.id
        ).execute

        premium_plan = find_plan(plans_data, ::GitlabSubscriptions::SystemDefined::Plan::PREMIUM) if plans_data
        ::GitlabSubscriptions::PurchaseUrlBuilder.new(plan_id: premium_plan&.id, namespace: root_namespace).build
      end

      private

      def root_namespace
        @source&.root_ancestor
      end

      def find_plan(plans_data, plan_code)
        plans_data.find { |plan| plan.code == plan_code }
      end
    end

    class SelfManagedStrategy
      def initialize(user)
        @user = user
      end

      def can_buy_addon?
        @user.can_admin_all_resources?
      end

      def expired_buy_path
        ::Gitlab::Routing.url_helpers.subscription_portal_url
      end
    end
  end
end
