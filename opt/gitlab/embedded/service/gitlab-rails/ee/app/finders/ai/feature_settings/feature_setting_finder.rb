# frozen_string_literal: true

module Ai
  module FeatureSettings
    class FeatureSettingFinder
      def initialize(self_hosted_model_id: nil)
        @self_hosted_model_id = self_hosted_model_id.model_id if self_hosted_model_id.is_a?(::GlobalID)

        @self_hosted_model_id ||= self_hosted_model_id
      end

      def execute
        feature_settings = get_feature_settings
        partition_by_feature_scope(feature_settings)
      end

      private

      def dap_features
        %w[
          duo_agent_platform
          duo_agent_platform_agentic_chat
          duo_developer
          recommend_reviewers_assign
          risk_classification
        ]
      end

      def semantic_search_features
        %w[embeddings_code]
      end

      def partition_by_feature_scope(feature_settings)
        {
          dap: feature_settings.select { |setting| dap_features.include?(setting.feature) },
          semantic_search: feature_settings.select do |setting|
            semantic_search_features.include?(setting.feature)
          end,
          classic: feature_settings.reject do |setting|
            dap_features.include?(setting.feature) ||
              semantic_search_features.include?(setting.feature)
          end
        }
      end

      def get_feature_settings
        return scope_all unless @self_hosted_model_id # return type of scope_all is Array

        scope_for_self_hosted_model(@self_hosted_model_id).to_a # .to_a to keep the return type consistent
      end

      def scope_for_self_hosted_model(self_hosted_model_id)
        ::Ai::FeatureSetting.for_self_hosted_model(self_hosted_model_id)
      end

      def scope_all
        feature_settings_by_name = ::Ai::FeatureSetting.all.index_by(&:feature)

        ::Ai::FeatureSetting.allowed_features.keys.map do |feature|
          feature_settings_by_name[feature.to_s] || ::Ai::FeatureSetting.new(feature: feature)
        end
      end
    end
  end
end
