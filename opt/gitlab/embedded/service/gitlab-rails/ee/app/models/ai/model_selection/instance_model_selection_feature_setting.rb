# frozen_string_literal: true

module Ai
  module ModelSelection
    class InstanceModelSelectionFeatureSetting < ApplicationRecord
      include ::Ai::ModelSelection::FeaturesConfigurable
      include ::Ai::ModelSelection::ModelAllowlist

      self.table_name = "instance_model_selection_feature_settings"

      validates :feature, uniqueness: true

      def self.find_or_initialize_by_feature(feature)
        feature_name = get_feature_name(feature)
        find_or_initialize_by(feature: feature_name)
      end

      def build_with_offered_model_ref(offered_model_ref)
        self.class.build(feature: feature, offered_model_ref: offered_model_ref)
      end

      def base_url
        ::Gitlab::AiGateway.cloud_connector_url
      end

      def vendored?
        true
      end
    end
  end
end
