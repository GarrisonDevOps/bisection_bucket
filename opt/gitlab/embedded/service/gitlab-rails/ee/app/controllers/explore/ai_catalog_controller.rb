# frozen_string_literal: true

module Explore
  class AiCatalogController < Explore::ApplicationController
    feature_category :ai_catalog_curation
    before_action :check_ai_catalog_availability!
    before_action :set_instance_beta_features_enabled
    before_action do
      push_frontend_feature_flag(:ai_catalog_third_party_flows, current_user)
      push_frontend_feature_flag(:ai_catalog_create_third_party_flows, current_user)
      push_frontend_feature_flag(:ai_catalog_mcp_servers, current_user)
      push_frontend_feature_flag(:ai_catalog_flow_agent_references, current_user)
      push_frontend_feature_flag(:ai_catalog_synthetic_foundational_items, current_user)
      push_frontend_feature_flag(:ai_catalog_unified_views, current_user)
      push_frontend_feature_flag(:duo_agentic_chat_prefer_mcp_tools, current_user)
      push_frontend_feature_flag(:ai_flow_schedules, current_user)
      push_frontend_feature_flag(:autonomous_service_account_execution, current_user)
      push_frontend_feature_flag(:ai_catalog_skills, current_user)
      push_frontend_ability(ability: :read_ai_catalog_mcp_server, resource: ::Current.organization, user: current_user)
      push_frontend_ability(ability: :create_ai_catalog_mcp_server, resource: ::Current.organization,
        user: current_user)
      push_frontend_ability(ability: :update_ai_catalog_mcp_server, resource: ::Current.organization,
        user: current_user)
      push_frontend_ability(ability: :read_ai_catalog, user: current_user)
      push_frontend_ability(ability: :report_ai_catalog_item, user: current_user)
      push_frontend_ability(ability: :force_hard_delete_ai_catalog_item, user: current_user)
    end

    private

    def check_ai_catalog_availability!
      render_404 unless ::Ai::Catalog.feature_available?
    end

    def set_instance_beta_features_enabled
      @instance_beta_features_enabled = current_user.present? &&
        ::Ai::Catalog.user_can_access_experimental_and_beta_features?(current_user)
    end
  end
end
