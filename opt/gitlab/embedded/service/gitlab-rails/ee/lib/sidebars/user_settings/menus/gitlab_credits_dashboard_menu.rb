# frozen_string_literal: true

module Sidebars # rubocop:disable Gitlab/BoundedContexts -- Existing module
  module UserSettings
    module Menus
      class GitlabCreditsDashboardMenu < ::Sidebars::Menu
        override :link
        def link
          profile_gitlab_credits_dashboard_index_path
        end

        override :title
        def title
          s_('UsageBilling|GitLab Credits')
        end

        override :sprite_icon
        def sprite_icon
          'gitlab-credits'
        end

        override :render?
        def render?
          user = context.current_user

          return false unless user&.human?
          return false unless ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)

          user.groups_with_gitlab_credits.any?
        end

        override :active_routes
        def active_routes
          { controller: :gitlab_credits_dashboard }
        end
      end
    end
  end
end
