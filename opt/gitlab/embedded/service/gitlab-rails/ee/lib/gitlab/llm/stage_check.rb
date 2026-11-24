# frozen_string_literal: true

module Gitlab
  module Llm
    class StageCheck
      CREDITS_ELIGIBLE_FEATURES = %i[
        agentic_chat
        ai_catalog
        ai_catalog_flows
        ai_catalog_third_party_flows
        ai_catalog_mcp_servers
        ai_catalog_flow_agent_references
        duo_workflow
        foundational_flows
      ].freeze

      class << self
        # @param container [Group, Project]
        # @param feature [Symbol]
        def available?(container, feature)
          root_ancestor = container.root_ancestor

          return false if personal_namespace?(root_ancestor)

          # Allow free-tier namespaces/instances with an active gitlab_credits add-on
          # to access credits-eligible DAP features without a paid license (SaaS and SM).
          return false unless root_ancestor.licensed_feature_available?(license_feature_name(feature)) ||
            credits_access?(root_ancestor, feature)

          available_on_experimental_stage?(root_ancestor, feature) ||
            available_on_beta_stage?(root_ancestor, feature) ||
            available_on_ga_stage?(feature)
        end

        private

        def personal_namespace?(root_ancestor)
          root_ancestor.user_namespace?
        end

        def saas?
          ::Gitlab::Saas.feature_available?(:gitlab_duo_saas_only)
        end

        def credits_eligible_feature?(feature)
          CREDITS_ELIGIBLE_FEATURES.include?(feature)
        end

        def credits_access?(root_ancestor, feature)
          credits_eligible_feature?(feature) && root_ancestor.has_active_gitlab_credits_add_on?
        end

        def available_on_experimental_stage?(root_ancestor, feature)
          return false unless instance_allows_experiment_and_beta_features
          return false unless gitlab_com_namespace_enables_experiment_and_beta_features(root_ancestor)
          return false unless available_on_stage?(feature, :experimental)

          true
        end

        # There is no beta setting yet.
        # https://gitlab.com/gitlab-org/gitlab/-/issues/409929
        def available_on_beta_stage?(root_ancestor, feature)
          return false unless instance_allows_experiment_and_beta_features
          return false unless gitlab_com_namespace_enables_experiment_and_beta_features(root_ancestor)
          return false unless available_on_stage?(feature, :beta)

          true
        end

        def available_on_ga_stage?(feature)
          return true if available_on_stage?(feature, :ga)

          false
        end

        def license_feature_name(feature)
          case feature
          when :chat
            :ai_chat
          when :agentic_chat
            :agentic_chat
          when :ai_catalog, :ai_catalog_flows, :ai_catalog_third_party_flows, :ai_catalog_mcp_servers,
            :ai_catalog_flow_agent_references
            :ai_catalog
          when :duo_workflow, :foundational_flows
            :ai_workflows
          when :glab_ask_git_command
            :glab_ask_git_command
          when :generate_commit_message
            :generate_commit_message
          when :summarize_new_merge_request
            :summarize_new_merge_request
          when :summarize_review
            :summarize_review
          when :generate_description
            :generate_description
          when :summarize_comments
            :summarize_comments
          when :review_merge_request
            :review_merge_request
          else
            :ai_features
          end
        end

        def instance_allows_experiment_and_beta_features
          if ::Gitlab::Saas.feature_available?(:gitlab_duo_saas_only)
            true
          else
            ::Gitlab::CurrentSettings.instance_level_ai_beta_features_enabled?
          end
        end

        def gitlab_com_namespace_enables_experiment_and_beta_features(namespace)
          # namespace-level settings check is only relevant for .com
          return true unless ::Gitlab::Saas.feature_available?(:gitlab_duo_saas_only)

          if namespace.experiment_features_enabled
            true
          else
            false
          end
        end

        def available_on_stage?(feature, maturity)
          ::Gitlab::Llm::Utils::AiFeaturesCatalogue::LIST.dig(feature, :maturity) == maturity
        end
      end
    end
  end
end

# Added for JiHu
::Gitlab::Llm::StageCheck.prepend_mod
