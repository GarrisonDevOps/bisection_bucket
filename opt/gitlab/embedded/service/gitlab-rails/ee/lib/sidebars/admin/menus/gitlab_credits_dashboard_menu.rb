# frozen_string_literal: true

module Sidebars # rubocop:disable Gitlab/BoundedContexts -- Existing module
  module Admin
    module Menus
      class GitlabCreditsDashboardMenu < ::Sidebars::Admin::BaseMenu
        override :link
        def link
          admin_gitlab_credits_dashboard_index_path
        end

        override :title
        def title
          _('GitLab Credits')
        end

        override :sprite_icon
        def sprite_icon
          'gitlab-credits'
        end

        override :active_routes
        def active_routes
          {
            controller: ['admin/gitlab_credits_dashboard', 'admin/gitlab_credits_dashboard/users']
          }
        end
      end
    end
  end
end
