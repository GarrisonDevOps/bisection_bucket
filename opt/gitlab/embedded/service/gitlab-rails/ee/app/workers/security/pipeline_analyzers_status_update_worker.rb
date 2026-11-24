# frozen_string_literal: true

module Security
  class PipelineAnalyzersStatusUpdateWorker
    include ApplicationWorker
    include Gitlab::ExclusiveLeaseHelpers

    data_consistency :sticky
    idempotent!
    feature_category :security_asset_inventories
    defer_on_database_health_signal :gitlab_sec, [:analyzer_namespace_statuses], 30.seconds

    LEASE_TTL = 5.minutes
    LEASE_TRY_AFTER = 2.seconds
    LEASE_RETRIES = 2
    RETRY_IN_IF_LOCKED = 10.seconds

    def perform(pipeline_id)
      pipeline = Ci::Pipeline.find_by_id(pipeline_id)
      return unless pipeline.present?

      return unless pipeline.project.licensed_feature_available?(:security_dashboard)

      root_namespace = pipeline.project.root_namespace
      perform_with_lock(pipeline, root_namespace.id)
    end

    private

    def perform_with_lock(pipeline, root_namespace_id)
      in_lock(lease_key(root_namespace_id), ttl: LEASE_TTL, sleep_sec: LEASE_TRY_AFTER, retries: LEASE_RETRIES) do
        AnalyzersStatus::UpdateService.new(pipeline).execute
      end
    rescue Gitlab::ExclusiveLeaseHelpers::FailedToObtainLockError
      self.class.perform_in(RETRY_IN_IF_LOCKED, pipeline.id)
    end

    def lease_key(root_namespace_id)
      "security:pipeline_analyzers_status_update_worker:#{root_namespace_id}"
    end
  end
end
