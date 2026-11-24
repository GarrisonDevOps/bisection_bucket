# frozen_string_literal: true

module EE
  module Gitlab
    module BackgroundMigration
      module BackfillTraversalIdsInSecurityScanProfilesProjects
        extend ActiveSupport::Concern
        extend ::Gitlab::Utils::Override

        # Compare-and-set: only update rows still holding the value read at pluck time, so a
        # concurrent transfer-sync write to the same column keeps its fresher value.
        UPDATE_SQL = <<~SQL
          WITH scan_profile_project_updates (id, expected_traversal_ids, traversal_ids) AS (
              %{with_values}
          )
            UPDATE
              security_scan_profiles_projects
            SET
              traversal_ids = scan_profile_project_updates.traversal_ids
            FROM
              scan_profile_project_updates
            WHERE
              scan_profile_project_updates.id = security_scan_profiles_projects.id AND
              security_scan_profiles_projects.traversal_ids = scan_profile_project_updates.expected_traversal_ids
        SQL

        class Namespace < ::ApplicationRecord
          self.table_name = 'namespaces'
          self.inheritance_column = :_type_disabled
        end

        class Project < ::ApplicationRecord
          self.table_name = 'projects'

          belongs_to :namespace,
            class_name: 'EE::Gitlab::BackgroundMigration::' \
              'BackfillTraversalIdsInSecurityScanProfilesProjects::Namespace'

          scope :joins_namespace, -> { joins(:namespace) }
          # rubocop: disable CodeReuse/ActiveRecord -- redefining to avoid using application code in migration
          scope :traversal_ids_by_project, ->(project_ids) {
            where(id: project_ids).joins_namespace.limit(project_ids.length)
                                  .pluck(:id, 'namespaces.traversal_ids')
          }
          # rubocop: enable CodeReuse/ActiveRecord
        end

        prepended do
          cursor :id
          operation_name :backfill_traversal_ids_in_security_scan_profiles_projects
          feature_category :security_asset_inventories
        end

        override :perform
        def perform
          each_sub_batch do |sub_batch|
            # rubocop:disable CodeReuse/ActiveRecord -- specific for this backfill
            rows = sub_batch.pluck(:id, :project_id, :traversal_ids)
            # rubocop:enable CodeReuse/ActiveRecord

            values_sql = rows_to_values_sql(rows)
            next if values_sql.blank?

            ::SecApplicationRecord.connection.execute(format(UPDATE_SQL, with_values: values_sql))
          end
        end

        private

        # Rows already holding the correct value are dropped here rather than in the
        # statement, so they never reach the CTE and cost nothing to skip.
        def rows_to_values_sql(rows)
          project_ids = rows.map { |_id, project_id, _traversal_ids| project_id }.uniq
          traversal_ids_by_project = Project.traversal_ids_by_project(project_ids).to_h

          values = rows.filter_map do |id, project_id, row_traversal_ids|
            project_traversal_ids = traversal_ids_by_project[project_id]
            next if project_traversal_ids.nil? || project_traversal_ids == row_traversal_ids

            [
              Integer(id),
              Arel.sql("ARRAY#{row_traversal_ids}::bigint[]"),
              Arel.sql("ARRAY#{project_traversal_ids}::bigint[]")
            ]
          end

          return if values.empty?

          Arel::Nodes::ValuesList.new(values).to_sql
        end
      end
    end
  end
end
