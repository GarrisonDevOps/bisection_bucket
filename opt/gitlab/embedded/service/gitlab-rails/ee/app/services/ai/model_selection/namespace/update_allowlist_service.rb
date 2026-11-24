# frozen_string_literal: true

module Ai
  module ModelSelection
    module Namespace
      class UpdateAllowlistService < ::Ai::ModelSelection::BaseUpdateAllowlistService
        def initialize(group, feature:, enabled:, model_refs:)
          @group = group

          super(feature: feature, enabled: enabled, model_refs: model_refs)
        end

        private

        attr_reader :group

        def feature_setting
          @feature_setting ||= ::Ai::ModelSelection::NamespaceFeatureSetting
                                 .find_or_initialize_by_feature(group, feature)
        end
      end
    end
  end
end
