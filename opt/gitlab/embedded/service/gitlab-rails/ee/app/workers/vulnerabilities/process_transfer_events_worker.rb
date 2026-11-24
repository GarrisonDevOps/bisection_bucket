# frozen_string_literal: true

module Vulnerabilities
  class ProcessTransferEventsWorker
    include Gitlab::EventStore::Subscriber

    BATCH_SIZE = 1_000

    idempotent!
    deduplicate :until_executing, including_scheduled: true
    data_consistency :always

    feature_category :vulnerability_management

    def handle_event(event)
      project_ids(event).each_slice(BATCH_SIZE) do |slice|
        bulk_schedule_vulnerability_reads_worker(slice)
        bulk_schedule_vulnerability_statistics_worker(slice)
      end
    end

    private

    def bulk_schedule_vulnerability_reads_worker(project_ids)
      # rubocop:disable Scalability/BulkPerformWithContext -- allow context omission
      Vulnerabilities::UpdateNamespaceIdsOfVulnerabilityReadsWorker.bulk_perform_async(project_ids.zip)
      # rubocop:enable Scalability/BulkPerformWithContext
    end

    def bulk_schedule_vulnerability_statistics_worker(project_ids)
      # rubocop:disable Scalability/BulkPerformWithContext -- allow context omission
      Vulnerabilities::UpdateTraversalIdsOfVulnerabilityStatisticWorker.bulk_perform_async(project_ids.zip)
      # rubocop:enable Scalability/BulkPerformWithContext
    end

    def project_ids(event)
      case event
      when ::Projects::ProjectTransferedEvent
        vulnerable_project_ids(event.data[:project_id])
      when ::Groups::GroupTransferedEvent
        group = Group.find_by_id(event.data[:group_id])

        return [] unless group

        Gitlab::Database::NamespaceProjectIdsEachBatch.new(
          group_id: group.id,
          resolver: method(:vulnerable_project_ids)
        ).execute
      end
    end

    def vulnerable_project_ids(batch)
      ProjectSetting.for_projects(batch)
                    .has_vulnerabilities
                    .pluck_primary_key
    end
  end
end
