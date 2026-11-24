# frozen_string_literal: true

module Search
  module Elastic
    class DestroyExpiredSubscriptionService
      include ::Gitlab::ExclusiveLeaseHelpers

      MAX_NAMESPACES_TO_REMOVE = 400
      DELETE_BATCH_SIZE = 50
      DELAY_INTERVAL = 5.minutes

      def execute
        return 0 unless ::Gitlab::Saas.feature_available?(:advanced_search)

        namespaces_removed = 0

        in_lock(self.class.name.underscore, ttl: 1.hour, retries: 0) do
          before_date = Time.zone.today - ElasticsearchIndexedNamespace::EXPIRED_SUBSCRIPTION_GRACE_PERIOD

          ElasticsearchIndexedNamespace.each_batch(column: :namespace_id) do |batch|
            namespace_ids = batch.pluck_primary_key

            namespace_with_subscription_ids = GitlabSubscription.namespace_id_in(namespace_ids)
                                                                .with_a_paid_or_trial_hosted_plan
                                                                .not_expired(before_date: before_date)
                                                                .pluck(:namespace_id) # rubocop: disable Database/AvoidUsingPluckWithoutLimit, CodeReuse/ActiveRecord -- limited by each_batch already

            namespace_to_remove_ids = (namespace_ids - namespace_with_subscription_ids)
              .first(MAX_NAMESPACES_TO_REMOVE - namespaces_removed)
            next if namespace_to_remove_ids.empty?

            namespace_to_remove_ids.each_slice(DELETE_BATCH_SIZE) do |ids|
              namespaces_removed += ElasticsearchIndexedNamespace.primary_key_in(ids).delete_all
            end

            bulk_args = namespace_to_remove_ids.map { |id| [id, :delete] }

            # rubocop:disable Scalability/BulkPerformWithContext -- Instantiating namespaces just for logs is wasteful.
            # The namespace that this ran on can be determined via the args.
            ElasticNamespaceIndexerWorker.bulk_perform_in(DELAY_INTERVAL, bulk_args)
            # rubocop:enable Scalability/BulkPerformWithContext

            break if namespaces_removed >= MAX_NAMESPACES_TO_REMOVE
          end
        rescue Gitlab::ExclusiveLeaseHelpers::FailedToObtainLockError
          # do nothing
        end

        namespaces_removed
      end
    end
  end
end
