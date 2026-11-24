# frozen_string_literal: true

module EE
  module Gitlab
    module GonHelper
      extend ::Gitlab::Utils::Override

      override :add_gon_variables
      def add_gon_variables
        super

        gon.roadmap_epics_limit = 1000

        if current_user && defined?(Llm)
          ai_chat = {
            total_model_token: ::Llm::ExplainCodeService::TOTAL_MODEL_TOKEN_LIMIT,
            max_response_token: ::Llm::ExplainCodeService::MAX_RESPONSE_TOKENS,
            input_content_limit: ::Llm::ExplainCodeService::INPUT_CONTENT_LIMIT
          }

          push_to_gon_attributes('ai', 'chat', ai_chat)
        end

        push_frontend_feature_flags
        push_orbit_availability

        # Used by Self-Managed customers
        gon.subscriptions_url = ::Gitlab::Routing.url_helpers.subscription_portal_url

        return unless ::Gitlab.com?

        gon.subscriptions_legacy_sign_in_url = ::Gitlab::Routing.url_helpers.subscription_portal_legacy_sign_in_url
        gon.billing_accounts_url             = ::Gitlab::Routing.url_helpers.subscription_portal_billing_accounts_url
        gon.is_gitlab_team_member            = current_user.present? && ::Gitlab::Com.gitlab_com_group_member?(current_user)
      end

      def push_frontend_feature_flags
        push_frontend_feature_flag(:advanced_context_resolver, current_user)

        push_frontend_feature_flag(:duo_chat_binary_feedback, current_user)
        push_frontend_feature_flag(:duo_chat_clarification_question_tool, current_user)
        push_frontend_feature_flag(:agentic_chat_flow_registry_migration, current_user)
        push_frontend_feature_flag(:no_duo_classic_for_duo_core_users, current_user)
        push_frontend_feature_flag(:dap_session_restarts, current_user)
        push_frontend_feature_flag(:dap_group_session_links, current_user)
        push_frontend_feature_flag(:duo_workflow_project_search_guard, current_user)
        push_frontend_feature_flag(:dap_session_load_more_messages, current_user)
        push_frontend_feature_flag(:dap_web_search, current_user)
        push_frontend_feature_flag(:dap_web_chat_file_attachments, current_user)
        push_frontend_feature_flag(:duo_workflow_session_file_persistent_uploads, current_user)
        push_frontend_feature_flag(:new_model_selection, current_user)
        push_frontend_feature_flag(:duo_chat_redesign, current_user)
        push_frontend_feature_flag(:duo_chat_lazy_load_messages, current_user)
        push_frontend_feature_flag(:session_details_enhancements, current_user)
        push_frontend_feature_flag(:mfe_duo_chat_poc, current_user)
      end

      # Only advertise Orbit where the Knowledge Graph service is configured, else
      # the toggle surfaces although the backend gates always return false.
      def push_orbit_availability
        gon.orbit_available = ::Analytics::KnowledgeGraph.service_configured?
      end

      # Exposes if a licensed feature is available.
      #
      # name - The name of the licensed feature
      # obj  - the object to check the licensed feature on (project, namespace)
      def push_licensed_feature(name, obj = nil)
        enabled = if obj
                    obj.feature_available?(name)
                  else
                    ::License.feature_available?(name)
                  end

        push_to_gon_attributes(:licensed_features, name, enabled)
      end

      # Exposes if a SaaS feature is available.
      #
      # name - The name of the SaaS feature
      def push_saas_feature(name)
        push_to_gon_attributes(:saas_features, name, ::Gitlab::Saas.feature_available?(name))
      end

      def push_dedicated_feature(name)
        push_to_gon_attributes(:dedicated_features, name, ::Gitlab::Dedicated.feature_available?(name))
      end
    end
  end
end
