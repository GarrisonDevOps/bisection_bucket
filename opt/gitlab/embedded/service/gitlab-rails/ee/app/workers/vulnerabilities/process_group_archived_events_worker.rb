# frozen_string_literal: true

module Vulnerabilities
  class ProcessGroupArchivedEventsWorker
    include Gitlab::EventStore::Subscriber

    idempotent!
    deduplicate :until_executing, including_scheduled: true
    data_consistency :always

    feature_category :vulnerability_management

    BATCH_SIZE = 100

    # Queues the archived attribute updates for the projects in the archived or unarchived group's subtree.
    #
    # @param event [Namespaces::Groups::GroupArchivedEvent]
    # @return [void]
    def handle_event(event)
      return unless event.data[:group_id]

      namespace_id = event.data[:group_id]
      only_vulnerable_projects = skip_projects_without_vulnerabilities?(namespace_id)

      cursor = { current_id: namespace_id, depth: [namespace_id] }
      iterator = Gitlab::Database::NamespaceEachBatch.new(namespace_class: Group, cursor: cursor)

      iterator.each_batch(of: BATCH_SIZE) do |ids, _new_cursor|
        Project.in_namespace(ids).each_batch(of: BATCH_SIZE) do |project_batch|
          project_batch = project_batch.has_vulnerabilities if only_vulnerable_projects

          bulk_schedule_vulnerability_reads_worker(project_batch)
          bulk_schedule_vulnerability_statistics_worker(project_batch)
        end
      end

      NamespaceStatistics::RecalculateNamespaceStatisticsWorker.perform_in(6.hours, namespace_id)
      nil
    end

    private

    # Checks the feature flag on the archived group, so it can be enabled for one group in a larger hierarchy.
    #
    # @param group_id [Integer]
    # @return [Boolean]
    def skip_projects_without_vulnerabilities?(group_id)
      Feature.enabled?(
        :skip_group_archive_jobs_for_projects_without_vulnerabilities,
        Group.actor_from_id(group_id)
      )
    end

    def bulk_schedule_vulnerability_reads_worker(projects)
      Vulnerabilities::UpdateArchivedAttributeOfVulnerabilityReadsWorker
        .bulk_perform_async_with_contexts(
          projects,
          arguments_proc: ->(project) { project.id },
          context_proc: ->(project) { { project: project } }
        )
    end

    def bulk_schedule_vulnerability_statistics_worker(projects)
      Vulnerabilities::UpdateArchivedAttributeOfVulnerabilityStatisticsWorker
        .bulk_perform_async_with_contexts(
          projects,
          arguments_proc: ->(project) { project.id },
          context_proc: ->(project) { { project: project } }
        )
    end
  end
end
