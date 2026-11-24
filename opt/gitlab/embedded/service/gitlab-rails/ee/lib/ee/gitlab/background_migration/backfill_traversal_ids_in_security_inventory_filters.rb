# frozen_string_literal: true

module EE
  module Gitlab
    module BackgroundMigration
      module BackfillTraversalIdsInSecurityInventoryFilters
        extend ActiveSupport::Concern
        extend ::Gitlab::Utils::Override

        class Namespace < ::Gitlab::Database::Migration[2.2]::MigrationRecord
          self.table_name = 'namespaces'
          self.inheritance_column = :_type_disabled
        end

        class Project < ::Gitlab::Database::Migration[2.2]::MigrationRecord
          self.table_name = 'projects'

          belongs_to :namespace
          scope :joins_namespace, -> { joins(:namespace) }
          # rubocop: disable CodeReuse/ActiveRecord -- redefining to avoid using application code in migration
          scope :namespace_traversal_ids, ->(project_ids) {
            where(id: project_ids).joins_namespace.limit(project_ids.length).pluck(:id, :traversal_ids)
          }
          # rubocop: enable CodeReuse/ActiveRecord
        end

        prepended do
          cursor :id
          operation_name :backfill_traversal_ids_in_security_inventory_filters
          feature_category :security_asset_inventories
        end

        override :perform
        def perform
          each_sub_batch { |sub_batch| reconcile_traversal_ids(sub_batch) }
        end

        private

        def reconcile_traversal_ids(sub_batch)
          # rubocop: disable CodeReuse/ActiveRecord -- avoid using application code in migration
          current_traversal_ids = sub_batch.pluck(:project_id, :traversal_ids)
          # rubocop: enable CodeReuse/ActiveRecord

          expected = Project.namespace_traversal_ids(current_traversal_ids.map(&:first)).to_h

          drifted = current_traversal_ids.filter_map do |project_id, traversal_ids|
            expected_ids = expected[project_id]
            next if expected_ids.nil? || expected_ids == traversal_ids

            [project_id, bigint_array(traversal_ids), bigint_array(expected_ids)]
          end
          return if drifted.empty?

          connection.execute(update_sql(drifted))
        end

        def bigint_array(ids)
          ::Arel.sql("ARRAY#{ids.map { |id| Integer(id) }}::bigint[]")
        end

        def update_sql(drifted)
          values = ::Arel::Nodes::ValuesList.new(drifted).to_sql

          # Match only the value observed by this job, leaving group-transferred rows untouched.
          <<~SQL
            UPDATE security_inventory_filters AS sif
            SET traversal_ids = v.traversal_ids
            FROM (#{values}) AS v(project_id, stale_traversal_ids, traversal_ids)
            WHERE sif.project_id = v.project_id
              AND sif.traversal_ids = v.stale_traversal_ids
          SQL
        end
      end
    end
  end
end
