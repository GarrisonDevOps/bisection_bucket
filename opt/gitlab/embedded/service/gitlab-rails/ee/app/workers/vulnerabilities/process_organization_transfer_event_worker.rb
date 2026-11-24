# frozen_string_literal: true

module Vulnerabilities
  # Re-indexes a transferred group's vulnerabilities so their Elasticsearch `organization_id`
  # (the org security dashboard's only scoping field) is refreshed from the new organization.
  # The transfer keeps the group top-level, so traversal_ids/routing are unchanged - only a
  # re-index is needed, not a traversal_ids update.
  class ProcessOrganizationTransferEventWorker
    include Gitlab::EventStore::Subscriber

    BATCH_SIZE = 1_000

    idempotent!
    deduplicate :until_executing, including_scheduled: true
    data_consistency :always

    feature_category :vulnerability_management

    # Gate enqueuing behind a feature flag so, during a rolling deploy, web nodes on new code do not
    # schedule this worker before it exists on every Sidekiq node. The flag is enabled only after the
    # deploy has fully rolled out. Evaluated by the event subscription before perform_async.
    # Memoized because a single transfer can publish one event per group via
    # Gitlab::EventStore.publish_group, and every event in that batch shares this organization.
    def self.dispatch?(event)
      organization_id = event.data[:new_organization_id]

      Gitlab::SafeRequestStore.fetch("#{name}:dispatch:#{organization_id}") do
        organization = ::Organizations::Organization.find_by_id(organization_id)

        ::Feature.enabled?(:reindex_vulnerabilities_on_organization_transfer, organization)
      end
    end

    def handle_event(event)
      return unless ::Search::Elastic::VulnerabilityIndexHelper.advanced_vulnerability_management_allowed?

      root_group = Group.find_by_id(event.data[:group_id])
      return unless root_group

      project_ids(root_group).each_slice(BATCH_SIZE) do |slice|
        # rubocop:disable Scalability/BulkPerformWithContext -- allow context omission
        Vulnerabilities::ReindexProjectVulnerabilitiesWorker.bulk_perform_async(slice.zip)
        # rubocop:enable Scalability/BulkPerformWithContext
      end
    end

    private

    def project_ids(root_group)
      Gitlab::Database::NamespaceProjectIdsEachBatch.new(
        group_id: root_group.id,
        resolver: method(:vulnerable_project_ids)
      ).execute
    end

    def vulnerable_project_ids(batch)
      ProjectSetting.for_projects(batch)
                    .has_vulnerabilities
                    .pluck_primary_key
    end
  end
end
