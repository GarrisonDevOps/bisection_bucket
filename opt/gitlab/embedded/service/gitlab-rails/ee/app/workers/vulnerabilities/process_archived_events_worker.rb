# frozen_string_literal: true

module Vulnerabilities
  # Ingest archived events to enqueue updating of denormalized column.
  # Check for presence of vulnerabilities to avoid redundant job queueing.

  class ProcessArchivedEventsWorker
    include Gitlab::EventStore::Subscriber

    idempotent!
    deduplicate :until_executing, including_scheduled: true
    data_consistency :sticky

    feature_category :vulnerability_management

    def handle_event(event)
      project_setting = ProjectSetting
        .select(:project_id)
        .has_vulnerabilities
        .find_by_project_id(event.data[:project_id])

      return unless project_setting

      handle_project_records(project_setting.project_id)
      # Handle namespace-level records after project records to ensure calculations use updated data.
      handle_namespace_records(event.data[:namespace_id])
    end

    def handle_project_records(project_id)
      Vulnerabilities::UpdateArchivedOfVulnerabilityReadsService.execute(project_id)
      Vulnerabilities::UpdateArchivedOfVulnerabilityStatisticsService.execute(project_id)
    end

    def handle_namespace_records(namespace_id)
      group = Group.find_by_id(namespace_id)
      return unless group

      NamespaceStatistics::RecalculateService.execute(group)
    end
  end
end
