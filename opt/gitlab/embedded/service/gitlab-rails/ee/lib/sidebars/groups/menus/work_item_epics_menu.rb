# frozen_string_literal: true

module Sidebars
  module Groups
    module Menus
      class WorkItemEpicsMenu < ::Sidebars::Menu
        include Gitlab::Utils::StrongMemoize

        override :configure_menu_items
        def configure_menu_items
          return false unless can?(context.current_user, :read_epic, context.group)

          add_item(work_item_list_menu_item)
          add_item(roadmap_menu_item)

          true
        end

        override :title
        def title
          context.is_super_sidebar ? _('Epic boards') : _('Boards')
        end

        override :sprite_icon
        def sprite_icon
          'work-item-epic'
        end

        override :active_routes
        def active_routes
          { controller: :epics }
        end

        override :has_pill?
        def has_pill?
          false
        end

        override :pill_count_field
        def pill_count_field
          'openEpicsCount'
        end

        override :serialize_as_menu_item_args
        def serialize_as_menu_item_args
          super.merge({
            pill_count: pill_count,
            pill_count_field: pill_count_field,
            has_pill: has_pill?,
            super_sidebar_parent: ::Sidebars::Groups::SuperSidebarMenus::PlanMenu,
            item_id: context.is_super_sidebar ? :epic_boards : :boards,
            link: group_epic_boards_path(context.group),
            description: _('Track epic progress on kanban-style boards'),
            library_icon: 'work-item-epic-board',
            tier: tier_for(:epics)
          })
        end

        private

        def work_item_list_menu_item
          ::Sidebars::MenuItem.new(
            title: s_('WorkItem|Work items'),
            link: group_work_items_path(context.group),
            super_sidebar_parent: ::Sidebars::Groups::SuperSidebarMenus::PlanMenu,
            active_routes: { path: 'work_items#index' },
            container_html_options: { class: 'js-super-sidebar-nav-item-hidden' },
            item_id: :group_epic_list,
            description: _('Break initiatives into smaller work items'),
            library_icon: 'work-item-epic',
            tier: tier_for(:epics)
          )
        end

        def roadmap_menu_item
          ::Sidebars::MenuItem.new(
            title: _('Roadmap'),
            link: group_roadmap_path(context.group),
            super_sidebar_parent: ::Sidebars::Groups::SuperSidebarMenus::PlanMenu,
            active_routes: { path: 'roadmap#show' },
            container_html_options: { class: 'home' },
            item_id: :roadmap,
            description: _("Plan your group's direction on a timeline"),
            library_icon: 'roadmap',
            tier: tier_for(:epics)
          )
        end
      end
    end
  end
end
