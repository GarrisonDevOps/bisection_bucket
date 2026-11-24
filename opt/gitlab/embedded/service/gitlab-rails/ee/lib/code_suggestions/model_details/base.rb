# frozen_string_literal: true

module CodeSuggestions
  module ModelDetails
    class Base
      include Gitlab::Utils::StrongMemoize

      def initialize(current_user:, feature_setting_name:, unit_primitive_name:, root_namespace: nil)
        @current_user = current_user
        @feature_setting_name = feature_setting_name
        @unit_primitive_name = unit_primitive_name
        @root_namespace = root_namespace
      end

      def feature_setting
        feature_setting_execution.payload
      end

      def base_url
        feature_setting&.base_url || ::Gitlab::AiGateway.url
      end

      def feature_name
        return :amazon_q_integration if ::Ai::AmazonQ.connected?

        :code_suggestions
      end

      def unit_primitive_name
        # We don't need to override this for SHM because this already happens
        # in UserAuthorizable.allowed_to_use.
        return :amazon_q_integration if ::Ai::AmazonQ.connected?

        @unit_primitive_name
      end

      def licensed_feature
        return :amazon_q if ::Ai::AmazonQ.connected?

        :ai_features
      end

      def feature_disabled?
        # In case the code suggestions feature is being used via self-hosted models,
        # it can also be disabled completely. In such cases, this check
        # can be used to prevent exposing the feature via UI/API.
        !!feature_setting&.disabled?
      end

      def self_hosted?
        !!feature_setting&.self_hosted?
      end

      def vendored?
        !!feature_setting&.vendored?
      end

      def default?
        return true unless feature_setting.present?
        return false unless vendored?
        return true if feature_setting.is_a?(Ai::FeatureSetting)

        feature_setting.set_to_gitlab_default?
      end

      def namespace_feature_setting?
        feature_setting.is_a?(::Ai::ModelSelection::NamespaceFeatureSetting)
      end

      def duo_context_not_found?
        return false if ::Ai::AmazonQ.connected?

        feature_setting_execution.error?
      end

      private

      attr_reader :current_user, :feature_setting_name, :root_namespace

      def feature_setting_execution
        ::Ai::FeatureSettingSelectionService.new(
          current_user,
          feature_setting_name,
          root_namespace
        ).execute
      end
      strong_memoize_attr :feature_setting_execution
    end
  end
end
