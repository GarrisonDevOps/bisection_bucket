# frozen_string_literal: true

module Projects
  class DuoAgentsPlatformController < Projects::ApplicationController
    extend Gitlab::Utils::Override
    include DuoWorkflowConcern

    DUO_AGENT_PLATFORM_ROUTES = %w[triggers agent-sessions].freeze

    feature_category :ai_catalog_curation
    before_action :check_access
    before_action do
      push_frontend_feature_flag(:ai_catalog_third_party_flows, current_user)
      push_frontend_feature_flag(:ai_catalog_synthetic_foundational_items, current_user)
      push_frontend_feature_flag(:ai_catalog_unified_views, current_user)
      push_frontend_feature_flag(:ai_catalog_group_inherited_consumers, project.root_ancestor)
      push_frontend_feature_flag(:duo_agentic_chat_prefer_mcp_tools, current_user)
      push_frontend_feature_flag(:dap_session_restarts, current_user)
      push_frontend_feature_flag(:dap_group_session_links, current_user)
      push_frontend_feature_flag(:ai_flow_schedules, project)
      push_frontend_feature_flag(:autonomous_service_account_execution, project)
      push_frontend_feature_flag(:duo_automations, current_user)
      push_frontend_feature_flag(:ai_flow_trigger_chaining, project.root_ancestor)
      push_force_frontend_feature_flag(:dap_software_factory, ::Gitlab::Ai::SoftwareFactory.enabled?(project))
      push_frontend_feature_flag(:ai_catalog_skills, project)
      push_force_frontend_feature_flag(:ai_catalog_flow_agent_references, agent_references_available?)
      push_frontend_ability(ability: :admin_ai_catalog_item, resource: project, user: current_user)
      push_frontend_ability(ability: :admin_ai_catalog_item_consumer, resource: project, user: current_user)
      push_frontend_ability(ability: :read_ai_catalog_flow, resource: project, user: current_user)
      push_frontend_ability(ability: :create_ai_catalog_flow, resource: project, user: current_user)
      push_frontend_ability(ability: :create_ai_catalog_agent, resource: project, user: current_user)
      push_frontend_ability(ability: :read_ai_foundational_flow, resource: project, user: current_user)
      push_frontend_ability(ability: :read_ai_catalog_third_party_flow, resource: project, user: current_user)
      push_frontend_ability(ability: :create_ai_catalog_third_party_flow, resource: project, user: current_user)
      push_frontend_ability(ability: :read_ai_catalog_mcp_server, resource: project, user: current_user)
      push_frontend_ability(ability: :manage_ai_flow_triggers, resource: project, user: current_user)
      push_frontend_ability(ability: :report_ai_catalog_item, user: current_user)
      push_frontend_ability(ability: :force_hard_delete_ai_catalog_item, user: current_user)
    end

    def show; end

    override :feature_category
    def feature_category
      if DUO_AGENT_PLATFORM_ROUTES.include?(duo_agents_platform_params[:vueroute])
        'duo_agent_platform'
      else
        super
      end
    end

    private

    # The editor support follows the check that the save services make.
    def agent_references_available?
      Feature.enabled?(:ai_catalog_flow_agent_references, project) &&
        ::Gitlab::Llm::StageCheck.available?(project, :ai_catalog_flow_agent_references)
    end

    def check_access
      return render_404 unless current_user

      if specific_vueroute?
        render_404 unless authorized_for_route?
        return
      end

      return render_404 unless duo_workflow_enabled?

      render_404 unless agent_session_readable?
    end

    def agent_session_id
      @agent_session_id ||= begin
        match = duo_agents_platform_params[:vueroute].to_s.match(%r{\Aagent-sessions/(\d+)\z})
        match[1] if match
      end
    end

    def agent_session_readable?
      return true unless agent_session_id

      workflow = ::Ai::DuoWorkflows::Workflow.find_in_project(project, agent_session_id)

      workflow.present? && can?(current_user, :read_duo_workflow, workflow)
    end

    def specific_vueroute?
      %w[agents flows skills triggers mcp-servers software-factory].include?(duo_agents_platform_params[:vueroute])
    end

    def authorized_for_route?
      case duo_agents_platform_params[:vueroute]
      when 'agents'
        true
      when 'triggers'
        Ability.allowed?(current_user, :read_ai_flow_triggers, project)
      when 'flows'
        Ability.allowed?(current_user, :read_ai_catalog_flow, project) ||
          Ability.allowed?(current_user, :read_ai_foundational_flow, project)
      when 'skills'
        ::Feature.enabled?(:ai_catalog_skills, project) &&
          Ability.allowed?(current_user, :read_ai_catalog_item, project)
      when 'mcp-servers'
        Ability.allowed?(current_user, :read_ai_catalog_mcp_server, project)
      when 'software-factory'
        software_factory_authorized?
      end
    end

    def software_factory_authorized?
      ::Gitlab::Ai::SoftwareFactory.enabled?(project) &&
        Ability.allowed?(current_user, :read_ai_flow_triggers, project) &&
        Ability.allowed?(current_user, :update_ai_flow_trigger, project)
    end

    def duo_agents_platform_params
      params.permit(:vueroute)
    end
  end
end
