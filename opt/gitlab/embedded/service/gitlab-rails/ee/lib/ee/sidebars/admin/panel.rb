# frozen_string_literal: true

module EE
  module Sidebars
    module Admin
      module Panel
        include ::GitlabSubscriptions::CodeSuggestionsHelper
        extend ::Gitlab::Utils::Override

        override :configure_menus
        def configure_menus
          super

          insert_menu_before(
            ::Sidebars::Admin::Menus::LabelsMenu,
            ::Sidebars::Admin::Menus::PushRulesMenu.new(context)
          )

          insert_menu_before(
            ::Sidebars::Admin::Menus::LabelsMenu,
            ::Sidebars::Admin::Menus::GeoMenu.new(context)
          )

          insert_menu_after(
            ::Sidebars::Admin::Menus::AbuseReportsMenu,
            ::Sidebars::Admin::Menus::SubscriptionMenu.new(context)
          )

          insert_gitlab_duo_menu
          insert_gitlab_credits_dashboard_menu
          insert_orbit_menu
        end

        private

        def insert_gitlab_duo_menu
          return unless License.current&.paid? || ::GitlabSubscriptions::Duo.active_self_managed_gitlab_credits?
          return if ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)

          insert_menu_after(
            ::Sidebars::Admin::Menus::SubscriptionMenu,
            ::Sidebars::Admin::Menus::DuoSettingsMenu.new(context)
          )
        end

        def insert_gitlab_credits_dashboard_menu
          return unless License.gitlab_credits_entitled?

          insert_menu_after(
            ::Sidebars::Admin::Menus::DuoSettingsMenu,
            ::Sidebars::Admin::Menus::GitlabCreditsDashboardMenu.new(context)
          )
        end

        def insert_orbit_menu
          return unless ::Ability.allowed?(context.current_user, :read_knowledge_graph_setting)

          insert_menu_after(
            ::Sidebars::Admin::Menus::DuoSettingsMenu,
            ::Sidebars::Admin::Menus::OrbitSettingsMenu.new(context)
          )
        end
      end
    end
  end
end
