# frozen_string_literal: true

module EE
  module Gitlab
    module BackgroundMigration
      module BackfillAnalyzerStatusesInSecurityInventoryFilters
        extend ActiveSupport::Concern
        extend ::Gitlab::Utils::Override

        # Maps analyzer_type enum values to security_inventory_filters column names.
        # From Enums::Security.extended_analyzer_types
        ANALYZER_TYPE_TO_COLUMN = {
          0 => 'sast',
          1 => 'sast_advanced',
          2 => 'sast_iac',
          3 => 'dast',
          4 => 'dependency_scanning',
          5 => 'container_scanning',
          6 => 'secret_detection',
          7 => 'coverage_fuzzing',
          8 => 'api_fuzzing',
          9 => 'cluster_image_scanning',
          10 => 'secret_detection_secret_push_protection',
          11 => 'container_scanning_for_registry',
          12 => 'secret_detection_pipeline_based',
          13 => 'container_scanning_pipeline_based'
        }.freeze

        # from Enums::Security::ANALYZER_STATUSES
        NOT_CONFIGURED = 0
        FAILED = 2
        STALE = 3

        prepended do
          operation_name :backfill_analyzer_statuses_in_security_inventory_filters
          feature_category :security_asset_inventories
        end

        override :perform
        def perform
          each_sub_batch do |sub_batch|
            changed_project_ids = reconcile_analyzer_statuses(sub_batch)
            recompute_aggregate_booleans(changed_project_ids) if changed_project_ids.any?
          end
        end

        private

        def reconcile_analyzer_statuses(sub_batch)
          result = connection.execute(build_update_sql(sub_batch))
          result.pluck('project_id')
        end

        def recompute_aggregate_booleans(project_ids)
          connection.execute(build_recompute_booleans_sql(project_ids))
        end

        def build_update_sql(sub_batch)
          project_ids_sql = sub_batch.select(:project_id).to_sql

          set_clauses = ANALYZER_TYPE_TO_COLUMN.map do |_type_value, column_name|
            "#{column_name} = COALESCE(agg.#{column_name}, sif.#{column_name})"
          end.join(",\n  ")

          pivot_columns = ANALYZER_TYPE_TO_COLUMN.map do |type_value, column_name|
            "MAX(CASE WHEN aps.analyzer_type = #{type_value} THEN aps.status END) AS #{column_name}"
          end.join(",\n    ")

          changed_filter = ANALYZER_TYPE_TO_COLUMN.map do |_type_value, column_name|
            "sif.#{column_name} IS DISTINCT FROM COALESCE(agg.#{column_name}, sif.#{column_name})"
          end.join("\n    OR ")

          <<~SQL
            UPDATE security_inventory_filters AS sif
            SET
              #{set_clauses}
            FROM (
              SELECT
                aps.project_id,
                #{pivot_columns}
              FROM analyzer_project_statuses AS aps
              WHERE aps.project_id IN (#{project_ids_sql})
              GROUP BY aps.project_id
            ) AS agg
            WHERE sif.project_id = agg.project_id
              AND (
                #{changed_filter}
              )
            RETURNING sif.project_id
          SQL
        end

        def build_recompute_booleans_sql(project_ids)
          columns = ANALYZER_TYPE_TO_COLUMN.values
          ids_list = project_ids.join(', ')

          has_scanners = columns.map { |c| "#{c} != #{NOT_CONFIGURED}" }.join(' OR ')
          has_failed = columns.map { |c| "#{c} = #{FAILED}" }.join(' OR ')
          has_stale = columns.map { |c| "#{c} = #{STALE}" }.join(' OR ')

          <<~SQL
            UPDATE security_inventory_filters
            SET
              has_scanners = (#{has_scanners}),
              has_failed_or_warning = (#{has_failed}),
              has_stale = (#{has_stale})
            WHERE project_id IN (#{ids_list})
          SQL
        end
      end
    end
  end
end
