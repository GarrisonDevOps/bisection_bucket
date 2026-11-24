# frozen_string_literal: true

module Gitlab
  module EventStore
    module Subscriptions
      class SbomSubscriptions < BaseSubscriptions
        def register
          store.subscribe ::Sbom::ProcessVulnerabilitiesWorker, to: ::Sbom::SbomIngestedEvent
          store.subscribe ::Sbom::CreateOccurrencesVulnerabilitiesWorker, to: ::Sbom::VulnerabilitiesCreatedEvent
          store.subscribe ::Sbom::ProcessTransferEventsWorker, to: ::Projects::ProjectTransferedEvent
          store.subscribe ::Sbom::ProcessTransferEventsWorker, to: ::Groups::GroupTransferedEvent
          store.subscribe ::Sbom::SyncArchivedStatusWorker, to: ::Projects::ProjectArchivedEvent
          store.subscribe ::Sbom::ProcessGroupArchivedEventsWorker,
            to: ::Namespaces::Groups::GroupArchivedEvent
          store.subscribe ::DependencyManagement::SecurityUpdate::SchedulerWorker,
            to: ::Sbom::SbomIngestedEvent
          store.subscribe ::Sbom::TrackPolicyDismissalOccurrenceRefsWorker,
            to: ::Security::PolicyDismissalPreservedEvent,
            if: ->(_event) {
              Feature.enabled?(:track_sbom_occurrence_refs_on_policy_dismissal_preserved, :instance) &&
                ::Search::Elastic::SbomOccurrenceRefIndexHelper.indexing_allowed?
            }
        end
      end
    end
  end
end
