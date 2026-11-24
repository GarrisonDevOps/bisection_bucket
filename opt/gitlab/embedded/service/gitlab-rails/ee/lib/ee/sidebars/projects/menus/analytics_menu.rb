# frozen_string_literal: true

module EE
  module Sidebars
    module Projects
      module Menus
        module AnalyticsMenu
          extend ::Gitlab::Utils::Override
          include ::Gitlab::Utils::StrongMemoize

          override :configure_menu_items
          def configure_menu_items
            return false unless can?(context.current_user, :read_analytics, context.project)

            add_item(dashboards_analytics_menu_item)
            add_item(cycle_analytics_menu_item)
            add_item(ci_cd_analytics_menu_item)
            add_item(code_review_analytics_menu_item)
            add_item(insights_menu_item)
            add_item(issues_analytics_menu_item)
            add_item(repository_analytics_menu_item)

            true
          end

          private

          def insights_menu_item
            unless context.project.insights_available?
              return ::Sidebars::NilMenuItem.new(item_id: :insights)
            end

            ::Sidebars::MenuItem.new(
              title: _('Insights'),
              link: project_insights_path(context.project),
              super_sidebar_parent: ::Sidebars::Projects::SuperSidebarMenus::AnalyzeMenu,
              active_routes: { path: 'insights#show' },
              container_html_options: { class: 'shortcuts-project-insights' },
              item_id: :insights,
              description: _('Build custom charts and reports'),
              library_icon: 'bulb',
              tier: tier_for(:insights)
            )
          end

          def code_review_analytics_menu_item
            unless can?(context.current_user, :read_code_review_analytics, context.project)
              return ::Sidebars::NilMenuItem.new(item_id: :code_review)
            end

            ::Sidebars::MenuItem.new(
              title: context.is_super_sidebar ? _('Code review analytics') : _('Code review'),
              link: project_analytics_code_reviews_path(context.project),
              super_sidebar_parent: ::Sidebars::Projects::SuperSidebarMenus::AnalyzeMenu,
              active_routes: { path: 'projects/analytics/code_reviews#index' },
              item_id: :code_review,
              description: _('Measure code review efficiency and throughput'),
              library_icon: 'code-review-analytics',
              tier: tier_for(:code_review_analytics)
            )
          end

          def issues_analytics_menu_item
            unless show_issues_analytics?
              return ::Sidebars::NilMenuItem.new(item_id: :issues)
            end

            ::Sidebars::MenuItem.new(
              title: context.is_super_sidebar ? _('Issue analytics') : _('Issue'),
              link: project_analytics_issues_analytics_path(context.project),
              super_sidebar_parent: ::Sidebars::Projects::SuperSidebarMenus::AnalyzeMenu,
              active_routes: { path: 'issues_analytics#show' },
              item_id: :issues,
              description: _('Track issue metrics, trends, and throughput'),
              library_icon: 'work-item-issue-analytics',
              tier: tier_for(:issues_analytics)
            )
          end

          def show_issues_analytics?
            context.project.licensed_feature_available?(:issues_analytics) &&
              can?(context.current_user, :read_issue_analytics, context.project)
          end

          def dashboards_analytics_menu_item
            unless context.project.licensed_feature_available?(:project_level_analytics_dashboard) &&
                can?(context.current_user, :read_project_level_analytics_dashboard, context.project) &&
                can?(context.current_user, :read_customizable_dashboards, context.project) && !context.project.personal?
              return ::Sidebars::NilMenuItem.new(item_id: :dashboards_analytics)
            end

            ::Sidebars::MenuItem.new(
              title: _('Analytics dashboards'),
              link: project_analytics_dashboards_path(context.project),
              super_sidebar_parent: ::Sidebars::Projects::SuperSidebarMenus::AnalyzeMenu,
              container_html_options: { class: 'shortcuts-project-dashboards-analytics' },
              active_routes: { path: 'projects/analytics/dashboards#index' },
              item_id: :dashboards_analytics,
              description: _('Create and manage custom analytics dashboards'),
              library_icon: 'chart',
              tier: tier_for(:project_level_analytics_dashboard)
            )
          end
          strong_memoize_attr :dashboards_analytics_menu_item
        end
      end
    end
  end
end
