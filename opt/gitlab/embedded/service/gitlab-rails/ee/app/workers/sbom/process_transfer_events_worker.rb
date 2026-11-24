# frozen_string_literal: true

module Sbom
  class ProcessTransferEventsWorker
    include Gitlab::EventStore::Subscriber

    idempotent!
    deduplicate :until_executing, including_scheduled: true
    data_consistency :always

    feature_category :dependency_management

    def handle_event(event)
      args = project_ids(event).zip

      # rubocop:disable Scalability/BulkPerformWithContext -- allow context omission
      ::Sbom::SyncProjectTraversalIdsWorker.bulk_perform_async(args)
      # rubocop:enable Scalability/BulkPerformWithContext
    end

    private

    def project_ids(event)
      case event
      when ::Projects::ProjectTransferedEvent
        project_id = event.data[:project_id]

        return [] unless Sbom::Occurrence.by_project_ids(project_id).exists?

        [project_id]
      when ::Groups::GroupTransferedEvent
        group = Group.find_by_id(event.data[:group_id])

        return [] unless group

        Gitlab::Database::NamespaceProjectIdsEachBatch.new(
          group_id: group.id,
          resolver: method(:project_ids_with_sbom_occurrences)
        ).execute
      end
    end

    # Given a batch of projects, filter to only return the project IDs that have Sbom::Occurrence records.
    def project_ids_with_sbom_occurrences(batch)
      # rubocop:disable CodeReuse/ActiveRecord -- Does not work outside this context.
      id_list = Arel::Nodes::ValuesList.new(batch.pluck_primary_key.map { |v| [v] }).to_sql
      filter_query = Sbom::Occurrence.where('project_ids.id = project_id').limit(1).select(1)

      Sbom::Occurrence.from(
        "(#{id_list}) AS project_ids(id), LATERAL (#{filter_query.to_sql}) AS #{Sbom::Occurrence.table_name}"
      ).pluck("project_ids.id")
      # rubocop:enable CodeReuse/ActiveRecord
    end
  end
end
