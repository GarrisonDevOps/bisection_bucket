# frozen_string_literal: true

module Gitlab
  module EventStore
    module Subscriptions
      class VulnerabilitiesSubscriptions < BaseSubscriptions
        def register
          store.subscribe ::Vulnerabilities::AutoDismissWorker,
            to: ::Sbom::VulnerabilitiesCreatedEvent
          store.subscribe ::Vulnerabilities::AutoSeverityOverrideWorker,
            to: ::Sbom::VulnerabilitiesCreatedEvent
          store.subscribe ::Vulnerabilities::ProcessTransferEventsWorker, to: ::Projects::ProjectTransferedEvent
          store.subscribe ::Vulnerabilities::ProcessTransferEventsWorker, to: ::Groups::GroupTransferedEvent
          # Each event costs a full group-tree traversal, so keep one per job. The default
          # group size of 10 would put ten traversals in a single low-urgency job.
          store.subscribe ::Vulnerabilities::ProcessOrganizationTransferEventWorker,
            to: ::Organizations::GroupTransferredEvent,
            group_size: 1,
            if: ->(event) { ::Vulnerabilities::ProcessOrganizationTransferEventWorker.dispatch?(event) }
          store.subscribe ::Vulnerabilities::ProcessArchivedEventsWorker, to: ::Projects::ProjectArchivedEvent
          store.subscribe ::Vulnerabilities::ProcessGroupArchivedEventsWorker,
            to: ::Namespaces::Groups::GroupArchivedEvent
          store.subscribe ::Vulnerabilities::ProcessBulkDismissedEventsWorker, to: ::Vulnerabilities::BulkDismissedEvent
          store.subscribe ::Vulnerabilities::ProcessBulkRedetectedEventsWorker,
            to: ::Vulnerabilities::BulkRedetectedEvent

          store.subscribe ::Vulnerabilities::NamespaceHistoricalStatistics::ProcessTransferEventsWorker,
            to: ::Groups::GroupTransferedEvent

          store.subscribe ::Vulnerabilities::NamespaceStatistics::ProcessProjectTransferEventsWorker,
            to: ::Projects::ProjectTransferedEvent
          store.subscribe ::Vulnerabilities::NamespaceStatistics::ProcessGroupTransferEventsWorker,
            to: ::Groups::GroupTransferedEvent

          store.subscribe ::Vulnerabilities::NamespaceStatistics::ProcessProjectDeleteEventsWorker,
            to: ::Projects::ProjectDeletedEvent
          store.subscribe ::Vulnerabilities::NamespaceStatistics::ProcessGroupDeleteEventsWorker,
            to: ::Groups::GroupDeletedEvent

          store.subscribe ::VulnerabilityExternalIssueLinks::UpdateVulnerabilityRead,
            to: ::Vulnerabilities::LinkToExternalIssueTrackerCreated

          store.subscribe ::VulnerabilityExternalIssueLinks::UpdateVulnerabilityRead,
            to: ::Vulnerabilities::LinkToExternalIssueTrackerRemoved
        end
      end
    end
  end
end
