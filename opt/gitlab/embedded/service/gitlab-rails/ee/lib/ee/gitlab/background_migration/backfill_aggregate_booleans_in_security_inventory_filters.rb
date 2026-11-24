# frozen_string_literal: true

module EE
  module Gitlab
    module BackgroundMigration
      module BackfillAggregateBooleansInSecurityInventoryFilters
        extend ActiveSupport::Concern
        extend ::Gitlab::Utils::Override

        ANALYZER_COLUMNS = %w[
          sast sast_advanced sast_iac dast dependency_scanning
          coverage_fuzzing api_fuzzing cluster_image_scanning
          secret_detection secret_detection_secret_push_protection
          secret_detection_pipeline_based container_scanning
          container_scanning_for_registry container_scanning_pipeline_based
        ].freeze

        # from Enums::Security::ANALYZER_STATUSES
        NOT_CONFIGURED = 0
        FAILED = 2
        STALE = 3

        prepended do
          operation_name :backfill_aggregate_booleans_in_security_inventory_filters
          feature_category :security_asset_inventories
        end

        override :perform
        def perform
          each_sub_batch do |sub_batch|
            sub_batch.update_all(recompute_sql)
          end
        end

        private

        def recompute_sql
          has_scanners = ANALYZER_COLUMNS.map { |column| "#{column} != #{NOT_CONFIGURED}" }.join(' OR ')
          has_failed = ANALYZER_COLUMNS.map { |column| "#{column} = #{FAILED}" }.join(' OR ')
          has_stale = ANALYZER_COLUMNS.map { |column| "#{column} = #{STALE}" }.join(' OR ')

          "has_scanners = (#{has_scanners}), " \
            "has_failed_or_warning = (#{has_failed}), " \
            "has_stale = (#{has_stale})"
        end
      end
    end
  end
end
