# frozen_string_literal: true

module Search
  module Elastic
    class IndexBulkCronWorker # rubocop:disable Scalability/IdempotentWorker -- cron worker
      include ::Elastic::BulkCronWorker

      worker_resource_boundary :cpu
      urgency :low
      defer_on_database_health_signal :gitlab_main
      data_consistency :sticky, feature_flag: :search_elastic_bulk_index_replica_reads

      private

      def service
        ::Elastic::ProcessBookkeepingService.new
      end

      # Sidekiq's scheduler pushes a requeue through the client middleware again, with its own flag check, so a
      # job requeued without a max score can still get WAL locations. It must not read an uncapped batch from a replica.
      def process_shard(shard_number, max_score = nil)
        return super if max_score

        ::Gitlab::Database::LoadBalancing::SessionMap
          .with_sessions(::Gitlab::Database::LoadBalancing.base_models)
          .use_primary { super }
      end

      def with_job_args(shard_number)
        return super unless self.class.get_data_consistency_feature_flag_enabled?

        # Only the primary's WAL location covers every ref at or below max_score.
        ::Gitlab::Database::LoadBalancing::SessionMap
          .with_sessions(::Gitlab::Database::LoadBalancing.base_models)
          .use_primary { yield [shard_number, service.class.max_score(shard_number)] }
      end
    end
  end
end
