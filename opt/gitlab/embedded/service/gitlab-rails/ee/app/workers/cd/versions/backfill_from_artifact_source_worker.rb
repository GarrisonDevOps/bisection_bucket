# frozen_string_literal: true

module Cd
  module Versions
    class BackfillFromArtifactSourceWorker
      include ApplicationWorker

      data_consistency :sticky
      feature_category :continuous_delivery
      worker_has_external_dependencies!
      urgency :low
      deduplicate :until_executed, including_scheduled: true
      concurrency_limit -> { 200 }
      idempotent!
      defer_on_database_health_signal :gitlab_main_org, [:cd_versions, :cd_artifact_sources]

      def perform(artifact_source_id)
        artifact_source = ::Cd::ArtifactSource.find_by_id(artifact_source_id)
        return unless artifact_source

        ::Cd::Versions::BackfillFromArtifactSourceService.new(artifact_source).execute
      end
    end
  end
end
