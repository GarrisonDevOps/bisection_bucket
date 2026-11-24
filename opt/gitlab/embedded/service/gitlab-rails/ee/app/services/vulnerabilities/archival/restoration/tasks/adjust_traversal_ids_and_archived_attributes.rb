# frozen_string_literal: true

module Vulnerabilities
  module Archival
    module Restoration
      module Tasks
        # If the project owning the vulnerability moved from a group to another,
        # the `traversal_ids` attribute would be diverged, therefore, we need to
        # update the `traversal_ids` of the `vulnerability_reads` records after
        # recovering them from the backups.
        # Same applies to the `archived` attribute which is also handled by this
        # service class.
        class AdjustTraversalIdsAndArchivedAttributes
          SQL_TEMPLATE = <<~SQL
            UPDATE
              vulnerability_reads
            SET
              traversal_ids = map.traversal_ids::bigint[],
              archived = map.archived
            FROM
              (%{values}) AS map(vulnerability_id, traversal_ids, archived)
            WHERE
              vulnerability_reads.vulnerability_id = map.vulnerability_id AND
              (
                vulnerability_reads.traversal_ids != map.traversal_ids::bigint[] OR
                vulnerability_reads.archived != map.archived
              )
          SQL

          def self.execute(...)
            new(...).execute
          end

          def initialize(vulnerability_backups)
            @vulnerability_backups = vulnerability_backups
          end

          def execute
            return unless update_data.present?

            update_vulnerability_reads
            ensure_consistency
          end

          private

          attr_reader :vulnerability_backups

          delegate :connection, :current_transaction, to: SecApplicationRecord, private: true

          def update_vulnerability_reads
            connection.execute(update_sql)
          end

          def update_sql
            format(SQL_TEMPLATE, values: values)
          end

          def values
            Arel::Nodes::ValuesList.new(update_data).to_sql
          end

          def update_data
            @update_data ||= vulnerability_backups.map do |backup|
              project = indexed_projects[backup.project_id]

              [
                backup.original_record_identifier,
                serialize_traversal_ids(project.namespace.traversal_ids),
                project.archived
              ]
            end
          end

          def indexed_projects
            @indexed_projects ||= projects.index_by(&:id)
          end

          def projects
            Project.id_in(project_ids).with_namespace
          end

          def project_ids
            vulnerability_backups.map(&:project_id).uniq
          end

          def serialize_traversal_ids(array)
            array_type_caster.serialize(array)
          end

          def array_type_caster
            @array_type_caster ||= Vulnerabilities::Read.type_for_attribute('traversal_ids')
          end

          # In this service class, we are naively trying to set the up-to-date values for `traversal_ids` and
          # `archived` attributes of `vulnerability_reads` records by loading the related projects into memory.
          # We have to load the projects into memory because that data lives in a separate database, which makes
          # it almost impossible to utilize PostgreSQL's ACID compliance.
          #
          # Since this operation is not atomic, those attributes can change after we set the values, which would
          # introduce a data consistency problem.
          # To address this, we check if the `traversal_ids` or `archived` attributes are changed after we update
          # the `vulnerability_reads` records. If they changed, we are scheduling an existing Sidekiq worker to fix
          # the data consistency problem.
          def ensure_consistency
            current_transaction.after_commit do
              ensure_traversal_ids_consistency
              ensure_archived_consistency
            end
          end

          def ensure_traversal_ids_consistency
            projects_which_traversal_ids_changed_after_update.each do |changed_project|
              Vulnerabilities::UpdateNamespaceIdsOfVulnerabilityReadsWorker.perform_async(changed_project.id)
            end
          end

          def ensure_archived_consistency
            projects_which_archived_changed_after_update.each do |changed_project|
              Vulnerabilities::ProcessArchivedEventsWorker.perform_async(
                'Projects::ProjectArchivedEvent',
                {
                  'namespace_id' => changed_project.namespace_id,
                  'root_namespace_id' => changed_project.namespace_id,
                  'project_id' => changed_project.id
                }
              )
            end
          end

          def projects_which_traversal_ids_changed_after_update
            projects_after_update.select do |project_after_update|
              project_before_update = indexed_projects[project_after_update.id]

              project_before_update.namespace.traversal_ids != project_after_update.namespace.traversal_ids
            end
          end

          def projects_which_archived_changed_after_update
            projects_after_update.select do |project_after_update|
              project_before_update = indexed_projects[project_after_update.id]

              project_before_update.archived != project_after_update.archived
            end
          end

          def projects_after_update
            @projects_after_update ||= projects.to_a
          end
        end
      end
    end
  end
end
