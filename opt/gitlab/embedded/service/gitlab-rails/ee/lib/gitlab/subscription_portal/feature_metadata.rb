# frozen_string_literal: true

module Gitlab
  module SubscriptionPortal
    class FeatureMetadata
      Feature = Struct.new(:feature_qualified_name, :feature_ai_catalog_item, keyword_init: true)

      # Registry of static feature names known to CDot as special cases
      FEATURES = {
        # CDot treats 'dap_feature_legacy' events as always billable.
        # We often sent this value instead of actual feature_qualified_name
        # due to the high complexity of resolving feature_qualified_name and feature_ai_catalog_item values.
        # This is the known behavior for CDot. Use this field with caution.
        # Ref: https://gitlab.com/gitlab-org/modelops/applied-ml/code-suggestions/ai-assist/-/merge_requests/4224
        dap_feature_legacy: Feature.new(
          feature_qualified_name: 'dap_feature_legacy',
          feature_ai_catalog_item: nil
        )
      }.freeze

      class << self
        # Get feature metadata by key
        # @param feature_key [Symbol] The feature identifier
        # @return [Feature, nil] The feature metadata or nil if not found
        def for(feature_key)
          FEATURES[feature_key]
        end
      end
    end
  end
end
