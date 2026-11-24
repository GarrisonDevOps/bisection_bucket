# frozen_string_literal: true

module Sbom
  class CreateOccurrencesVulnerabilitiesWorker
    include Gitlab::EventStore::Subscriber

    data_consistency :delayed
    feature_category :software_composition_analysis
    urgency :low
    deduplicate :until_executed
    idempotent!

    concurrency_limit -> { 200 }

    def handle_event(event)
      CreateOccurrencesVulnerabilitiesService.execute(event.data['findings'])
    end
  end
end
