# frozen_string_literal: true

module Ai
  module ModelSelection
    class UpdateInstanceAllowlistService < BaseUpdateAllowlistService
      private

      def feature_setting
        @feature_setting ||= ::Ai::ModelSelection::InstanceModelSelectionFeatureSetting
                               .find_or_initialize_by_feature(feature)
      end
    end
  end
end
