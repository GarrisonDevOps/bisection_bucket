# frozen_string_literal: true

module EE
  module Gitlab
    module BackgroundMigration
      module BackfillArchivedInSecurityInventoryFilters
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
          operation_name :backfill_archived_in_security_inventory_filters
          feature_category :security_asset_inventories
        end

        override :perform
        def perform
          each_sub_batch { |sub_batch| reconcile_archived(sub_batch) }
        end

        private

        def reconcile_archived(sub_batch)
          current_archived_by_project = sub_batch.pluck(:project_id, :archived).to_h
          effective_archived_by_project = fetch_effective_archived(current_archived_by_project.keys)

          to_archive = []
          to_unarchive = []

          current_archived_by_project.each do |project_id, archived|
            effective_archived = effective_archived_by_project[project_id]
            next if effective_archived.nil?
            next if archived == effective_archived

            effective_archived ? (to_archive << project_id) : (to_unarchive << project_id)
          end

          sub_batch.where(project_id: to_archive).update_all(archived: true) if to_archive.any?
          sub_batch.where(project_id: to_unarchive).update_all(archived: false) if to_unarchive.any?
        end

        def fetch_effective_archived(project_ids)
          effective_archived_sql = Arel.sql(
            "projects.archived OR EXISTS (#{Group.self_or_ancestors_archived_setting_subquery.to_sql})"
          )

          Project
            .where(id: project_ids)
            .left_joins(:group)
            .pluck(:id, effective_archived_sql)
            .to_h
        end
      end
    end
  end
end
