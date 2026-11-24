# frozen_string_literal: true

module EE
  module Gitlab
    module BackgroundMigration
      module BackfillArchivedInSecurityScanProfilesProjects
        extend ActiveSupport::Concern
        extend ::Gitlab::Utils::Override

        class NamespaceSetting < ::ApplicationRecord
          self.table_name = 'namespace_settings'
        end

        class Namespace < ::ApplicationRecord
          self.table_name = 'namespaces'
          self.inheritance_column = :_type_disabled

          has_one :namespace_settings, class_name: 'NamespaceSetting'

          def self.self_or_ancestors_archived_setting_subquery
            namespace_setting_reflection = reflect_on_association(:namespace_settings)
            namespace_setting_table = Arel::Table.new(namespace_setting_reflection.table_name)
            traversal_ids_ref = "#{arel_table.name}.#{arel_table[:traversal_ids].name}"

            namespace_setting_table
              .project(1)
              .where(
                namespace_setting_table[namespace_setting_reflection.foreign_key]
                  .eq(Arel.sql("ANY (#{traversal_ids_ref})"))
              )
              .where(namespace_setting_table[:archived].eq(true))
          end
        end

        class Group < Namespace
        end

        class Project < ::ApplicationRecord
          self.table_name = 'projects'

          belongs_to :group, -> { where(type: 'Group') }, foreign_key: 'namespace_id', class_name: 'Group'
        end

        prepended do
          cursor :id
          operation_name :backfill_archived_in_security_scan_profiles_projects
          feature_category :security_asset_inventories
        end

        override :perform
        def perform
          each_sub_batch { |sub_batch| reconcile_archived(sub_batch) }
        end

        private

        def reconcile_archived(sub_batch)
          project_ids = sub_batch.pluck(:project_id).uniq
          archived_ids, unarchived_ids = partition_by_archived(fetch_effective_archived(project_ids))

          update_rows(sub_batch, archived_ids, archived: true)
          update_rows(sub_batch, unarchived_ids, archived: false)
        end

        def partition_by_archived(effective_archived_by_project)
          effective_archived_by_project.partition { |_, archived| archived }.map { |pairs| pairs.map(&:first) }
        end

        def update_rows(sub_batch, project_ids, archived:)
          return if project_ids.empty?

          sub_batch.where(project_id: project_ids).where(archived: !archived).update_all(archived: archived)
        end

        def fetch_effective_archived(project_ids)
          effective_archived_sql = Arel.sql(
            "projects.archived OR EXISTS (#{Group.self_or_ancestors_archived_setting_subquery.to_sql})"
          )

          Project.where(id: project_ids).left_joins(:group).pluck(:id, effective_archived_sql).to_h
        end
      end
    end
  end
end
