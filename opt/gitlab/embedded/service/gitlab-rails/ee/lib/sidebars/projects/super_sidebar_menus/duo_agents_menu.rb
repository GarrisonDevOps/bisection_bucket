# frozen_string_literal: true

module Sidebars
  module Projects
    module SuperSidebarMenus
      class DuoAgentsMenu < ::Sidebars::Menu
        include DuoWorkflowConcern

        override :configure_menu_items
        def configure_menu_items
          return false unless current_user

          return false unless context.project.duo_features_enabled

          add_item(ai_catalog_agents_menu_item)
          add_item(ai_catalog_flows_menu_item) if show_flows_menu_item?
          add_item(ai_catalog_skills_menu_item) if show_skills_menu_item?
          add_item(duo_flow_triggers_menu_item) if show_flow_triggers_menu_items?
          add_item(software_factory_menu_item) if show_software_factory_menu_item?
          add_item(duo_agents_runs_menu_item) if show_agents_runs_menu_items?
          add_item(ai_catalog_mcp_servers_menu_item) if show_mcp_servers_menu_item?
          add_item(governance_menu_item) if show_governance_menu_item?

          true
        end

        override :title
        def title
          s_('DuoAgentsPlatform|AI')
        end

        override :sprite_icon
        def sprite_icon
          'tanuki-ai'
        end

        override :active_routes
        def active_routes
          { controller: :duo_agents_platform }
        end

        private

        def show_agents_runs_menu_items?
          duo_workflow_enabled?(context.project, context.current_user)
        end

        def show_flow_triggers_menu_items?
          Ability.allowed?(context.current_user, :read_ai_flow_triggers, context.project)
        end

        def show_software_factory_menu_item?
          ::Gitlab::Ai::SoftwareFactory.enabled?(context.project) &&
            show_flow_triggers_menu_items? &&
            Ability.allowed?(context.current_user, :update_ai_flow_trigger, context.project)
        end

        def show_flows_menu_item?
          Ability.allowed?(context.current_user, :read_ai_catalog_flow, context.project) ||
            Ability.allowed?(context.current_user, :read_ai_foundational_flow, context.project)
        end

        def show_skills_menu_item?
          ::Feature.enabled?(:ai_catalog_skills, context.project) &&
            Ability.allowed?(context.current_user, :read_ai_catalog_item, context.project)
        end

        def show_mcp_servers_menu_item?
          Ability.allowed?(context.current_user, :read_ai_catalog_mcp_server, context.project)
        end

        def show_governance_menu_item?
          ::Ai::Governance::PageAvailability.new(context.project, context.current_user).available?
        end

        def duo_agents_runs_menu_item
          link = project_automate_agent_sessions_path(context.project)

          ::Sidebars::MenuItem.new(
            title: s_('DuoAgentsPlatform|Sessions'),
            link: link,
            active_routes: { path_starts_with: link },
            item_id: :agents_runs,
            library_icon: 'session-ai',
            description: _('Monitor automation session history'),
            tier: :add_on
          )
        end

        def duo_flow_triggers_menu_item
          link = project_automate_flow_triggers_path(context.project)
          automations = Feature.enabled?(:duo_automations, context.current_user)

          ::Sidebars::MenuItem.new(
            title: automations ? s_('DuoAgentsPlatform|Automations') : s_('DuoAgentsPlatform|Triggers'),
            link: link,
            active_routes: { path_starts_with: link },
            item_id: :ai_flow_triggers,
            library_icon: automations ? 'bolt' : 'trigger-source',
            description: automations ? _('Manage AI flow automations') : _('Manage AI flow triggers'),
            tier: :add_on
          )
        end

        def software_factory_menu_item
          link = project_automate_software_factory_path(context.project)

          ::Sidebars::MenuItem.new(
            title: s_('DapSoftwareFactory|Software factory'),
            link: link,
            active_routes: { path_starts_with: link },
            item_id: :dap_software_factory,
            library_icon: 'dot-grid',
            description: s_('DapSoftwareFactory|Configure the software factory stages'),
            tier: :add_on
          )
        end

        def ai_catalog_agents_menu_item
          link = project_automate_agents_path(context.project)

          ::Sidebars::MenuItem.new(
            title: s_('AICatalog|Agents'),
            link: link,
            active_routes: { path_starts_with: link },
            item_id: :ai_catalog_agents,
            library_icon: 'agent-ai',
            description: _('Manage AI agents and flows'),
            tier: :add_on
          )
        end

        def ai_catalog_flows_menu_item
          link = project_automate_flows_path(context.project)

          ::Sidebars::MenuItem.new(
            title: s_('AICatalog|Flows'),
            link: link,
            active_routes: { path_starts_with: link },
            item_id: :ai_flows,
            library_icon: 'flow-ai',
            description: _('Manage AI flows'),
            tier: :add_on
          )
        end

        def ai_catalog_skills_menu_item
          link = project_automate_skills_path(context.project)

          ::Sidebars::MenuItem.new(
            title: s_('AICatalog|Skills'),
            link: link,
            active_routes: { path_starts_with: link },
            item_id: :ai_catalog_skills,
            library_icon: 'documents',
            description: s_('AICatalog|Browse skills published from project repositories'),
            tier: :add_on
          )
        end

        def ai_catalog_mcp_servers_menu_item
          link = project_automate_mcp_servers_path(context.project)

          ::Sidebars::MenuItem.new(
            title: s_('AICatalog|MCP servers'),
            link: link,
            active_routes: { path_starts_with: link },
            item_id: :ai_catalog_mcp_servers,
            library_icon: 'mcp',
            description: s_('AICatalog|Connect MCP servers to extend agent tooling'),
            tier: :add_on
          )
        end

        def governance_menu_item
          ::Sidebars::MenuItem.new(
            title: _('Governance'),
            link: project_automate_governance_path(context.project),
            active_routes: { path: 'projects/automate/governance#index' },
            item_id: :governance,
            library_icon: 'tanuki-ai',
            description: s_('AiGovernance|Monitor and control AI agents in your project'),
            tier: :add_on
          )
        end
      end
    end
  end
end
