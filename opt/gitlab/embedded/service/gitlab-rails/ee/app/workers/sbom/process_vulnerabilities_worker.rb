# frozen_string_literal: true

module Sbom
  class ProcessVulnerabilitiesWorker
    include Gitlab::EventStore::Subscriber

    data_consistency :delayed
    feature_category :software_composition_analysis
    urgency :low
    deduplicate :until_executed
    idempotent!

    def handle_event(event)
      CreateVulnerabilitiesService.execute(event.data[:pipeline_id])
    end
  end
end
