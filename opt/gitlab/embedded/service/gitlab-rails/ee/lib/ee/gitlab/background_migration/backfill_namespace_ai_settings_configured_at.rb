# frozen_string_literal: true

module EE
  module Gitlab
    module BackgroundMigration
      module BackfillNamespaceAiSettingsConfiguredAt
        extend ::ActiveSupport::Concern
        extend ::Gitlab::Utils::Override

        prepended do
          cursor :namespace_id
          operation_name :backfill_namespace_ai_settings_configured_at
          feature_category :compliance_management
        end

        # Hardcoded rather than read from Ai::NamespaceSetting: the configured_at schema only
        # allows these five keys, and app constants may change after this job ships.
        TRACKED_SETTINGS = %w[
          duo_workflow_mcp_enabled
          ai_usage_data_collection_enabled
          ai_catalog_restricted_to_group_hierarchy
          web_search_enabled
          prompt_injection_protection_level
        ].freeze

        override :perform
        def perform
          stamps = ::Gitlab::Json.dump(TRACKED_SETTINGS.index_with(Time.current.utc.iso8601))

          each_sub_batch do |sub_batch|
            # Filtered outside `sub_batch`, whose LIMIT would otherwise reach into the next sub-batch.
            # The right operand of `||` wins on key conflicts, so existing stamps are never overwritten.
            sub_batch.model
              .where(namespace_id: sub_batch.select(:namespace_id))
              .where('NOT jsonb_exists_all(configured_at, ARRAY[?])', TRACKED_SETTINGS)
              .update_all(['configured_at = ?::jsonb || configured_at', stamps])
          end
        end
      end
    end
  end
end
