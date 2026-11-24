# frozen_string_literal: true

module Ai
  module ModelSelection
    module Namespaces
      class FeatureSettingFinder
        def initialize(group:)
          @group = group
        end

        def execute
          return [] unless group&.root?

          scope_for_group.to_a # .to_a to keep the return type consistent
        end

        private

        attr_reader :group

        def scope_for_group
          feature_settings_by_name = group.ai_feature_settings.index_by(&:feature)

          ::Ai::ModelSelection::NamespaceFeatureSetting.enabled_features_for(group).keys.map do |feature|
            feature_settings_by_name[feature.to_s] || build_feature_setting(feature)
          end
        end

        def build_feature_setting(feature)
          ::Ai::ModelSelection::NamespaceFeatureSetting.new(namespace: group, feature: feature)
        end
      end
    end
  end
end
