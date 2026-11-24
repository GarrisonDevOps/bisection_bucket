# frozen_string_literal: true

module Gitlab
  module Llm
    class FeatureAuthorizer
      def initialize(container:, feature_name:, user:, licensed_feature: :ai_features)
        @container = container
        @feature_name = feature_name
        @user = user
        @licensed_feature = licensed_feature
      end

      def allowed?
        return false unless user
        return false unless container
        return false unless Gitlab::Llm::Utils::FlagChecker.flag_enabled_for_feature?(feature_name)

        return false unless user.allowed_to_use?(
          feature_name,
          licensed_feature: licensed_feature,
          root_namespace: container.root_ancestor
        )

        return false unless container.duo_features_enabled

        ::Gitlab::Llm::StageCheck.available?(container, feature_name)
      end

      private

      attr_reader :container, :feature_name, :user, :licensed_feature
    end
  end
end
