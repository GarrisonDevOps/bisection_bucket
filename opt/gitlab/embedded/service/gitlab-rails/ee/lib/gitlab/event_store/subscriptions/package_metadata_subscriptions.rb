# frozen_string_literal: true

module Gitlab
  module EventStore
    module Subscriptions
      class PackageMetadataSubscriptions < BaseSubscriptions
        def register
          store.subscribe ::PackageMetadata::GlobalAdvisoryScanWorker, to: ::PackageMetadata::IngestedAdvisoryEvent
          store.subscribe ::PackageMetadata::GlobalMalwareAdvisoryScanWorker,
            to: ::PackageMetadata::IngestedMalwareAdvisoryEvent
          store.subscribe ::PackageMetadata::ReindexMalwareAdvisoryOccurrenceRefsWorker,
            to: ::PackageMetadata::MalwareAdvisoryStatusChangedEvent,
            if: ->(_event) { ::Search::Elastic::SbomOccurrenceRefIndexHelper.indexing_allowed? }
        end
      end
    end
  end
end
