# frozen_string_literal: true

module Groups
  class DuoAgentsPlatformController < Groups::ApplicationController
    feature_category :ai_catalog_curation

    before_action :ensure_root_group
    before_action :check_access
    before_action do
      push_frontend_feature_flag(:ai_catalog_third_party_flows, current_user)
      push_frontend_feature_flag(:ai_catalog_synthetic_foundational_items, current_user)
      push_frontend_feature_flag(:ai_catalog_group_inherited_consumers, group)
      push_force_frontend_feature_flag(:ai_catalog_flow_agent_references, agent_references_available?)
      push_frontend_feature_flag(:duo_agentic_chat_prefer_mcp_tools, current_user)
      push_frontend_feature_flag(:duo_automations, current_user)
      push_frontend_feature_flag(:dap_session_restarts, current_user)
      push_frontend_feature_flag(:dap_group_session_links, current_user)
      push_force_frontend_feature_flag(:dap_software_factory, ::Gitlab::Ai::SoftwareFactory.enabled?(group))
      push_frontend_ability(ability: :admin_ai_catalog_item_consumer, resource: group, user: current_user)
      push_frontend_ability(ability: :read_ai_catalog_flow, resource: group, user: current_user)
      push_frontend_ability(ability: :read_ai_foundational_flow, resource: group, user: current_user)
      push_frontend_ability(ability: :read_ai_catalog_mcp_server, resource: group, user: current_user)
      push_frontend_ability(ability: :manage_ai_flow_triggers, resource: group, user: current_user)
      push_frontend_ability(ability: :report_ai_catalog_item, user: current_user)
      push_frontend_ability(ability: :force_hard_delete_ai_catalog_item, user: current_user)
    end

    def show; end

    private

    # The editor support follows the check that the save services make.
    def agent_references_available?
      Feature.enabled?(:ai_catalog_flow_agent_references, group) &&
        ::Gitlab::Llm::StageCheck.available?(group, :ai_catalog_flow_agent_references)
    end

    def check_access
      return render_404 unless current_user

      return unless specific_vueroute?

      render_404 unless authorized_for_route?
    end

    def ensure_root_group
      render_404 unless group.root?
    end

    def specific_vueroute?
      %w[agents flows mcp-servers].include?(duo_agents_platform_params[:vueroute])
    end

    def authorized_for_route?
      case duo_agents_platform_params[:vueroute]
      when 'agents'
        true
      when 'flows'
        Ability.allowed?(current_user, :read_ai_catalog_flow, group) ||
          Ability.allowed?(current_user, :read_ai_foundational_flow, group)
      when 'mcp-servers'
        Ability.allowed?(current_user, :read_ai_catalog_mcp_server, group)
      end
    end

    def duo_agents_platform_params
      params.permit(:vueroute)
    end
  end
end
