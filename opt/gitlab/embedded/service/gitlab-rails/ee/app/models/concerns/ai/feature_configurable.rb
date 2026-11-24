# frozen_string_literal: true

module Ai
  module FeatureConfigurable
    extend ActiveSupport::Concern

    FEATURE_METADATA_PATH = Rails.root.join('ee/lib/gitlab/ai/feature_settings/feature_metadata.yml')
    FEATURE_METADATA = YAML.load_file(FEATURE_METADATA_PATH)

    FeatureMetadata = Struct.new(
      :title,
      :main_feature,
      :compatible_llms,
      :release_state,
      :unit_primitives,
      keyword_init: true
    )

    def self_hosted?
      raise NotImplementedError, '#self_hosted? method must be implemented'
    end

    def disabled?
      raise NotImplementedError, '#disabled? method must be implemented'
    end

    def vendored?
      raise NotImplementedError, '#vendored? method must be implemented'
    end

    def model_metadata_params
      raise NotImplementedError, '#model_metadata_params method must be implemented'
    end

    def model_request_params
      raise NotImplementedError, '#model_request_params method must be implemented'
    end

    def base_url
      raise NotImplementedError, '#base_url method must be implemented'
    end

    included do
      def metadata
        feature_metadata = FEATURE_METADATA[feature.to_s] || {}

        FeatureMetadata.new(feature_metadata)
      end

      def user_model_selection_available?
        true
      end
    end
  end
end
