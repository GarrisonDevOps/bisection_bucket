# frozen_string_literal: true

module Sbom
  class SyncProjectTraversalIdsWorker
    include ApplicationWorker

    idempotent!
    deduplicate :until_executing, including_scheduled: true
    data_consistency :always

    feature_category :dependency_management

    def perform(project_id)
      ::Sbom::SyncTraversalIdsService.execute(project_id)
    end
  end
end
