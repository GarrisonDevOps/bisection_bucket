# frozen_string_literal: true

module Analytics
  module DevopsAdoption
    # Updates all pending snapshots for given enabled_namespace (from previous month)
    class CreateSnapshotWorker
      include ApplicationWorker
      include Gitlab::ExclusiveLeaseHelpers

      data_consistency :sticky

      sidekiq_options retry: 3

      feature_category :devops_reports
      idempotent!

      # Renewed before each pending range, so it only has to outlast one range's
      # subtree scan; a lease left by a killed job delays the namespace until the
      # next nightly CreateAllSnapshotsWorker pass.
      LEASE_TTL = 1.hour

      def perform(enabled_namespace_id)
        enabled_namespace = EnabledNamespace.find(enabled_namespace_id)

        unless Feature.enabled?(:devops_adoption_enabled_namespaces_cap, enabled_namespace.namespace)
          return create_snapshots(enabled_namespace)
        end

        with_namespace_lease(enabled_namespace) do |lease|
          create_snapshots(enabled_namespace, lease: lease)
        end
      end

      private

      # Snapshots are keyed by namespace_id, so rows for the same namespace under
      # different display namespaces must not calculate concurrently.
      def with_namespace_lease(enabled_namespace)
        in_lock(lease_key(enabled_namespace), ttl: LEASE_TTL, retries: 0) do |_retried, lease|
          yield lease
        end
      rescue Gitlab::ExclusiveLeaseHelpers::FailedToObtainLockError
        log_extra_metadata_on_done(:result, :skipped)
      end

      def create_snapshots(enabled_namespace, lease: nil)
        pending_ranges(enabled_namespace).each do |range_end|
          lease&.renew
          Snapshots::CalculateAndSaveService.new(enabled_namespace: enabled_namespace, range_end: range_end).execute
        end
      end

      def lease_key(enabled_namespace)
        "#{self.class.name.underscore}:#{enabled_namespace.namespace_id}"
      end

      # rubocop: disable CodeReuse/ActiveRecord
      def pending_ranges(enabled_namespace)
        end_times = enabled_namespace.snapshots.not_finalized.pluck(:end_time)

        prev_month = Time.current.last_month.end_of_month
        unless prev_month.to_date.in?(end_times.map(&:to_date)) || enabled_namespace.snapshots.for_month(prev_month).exists?
          end_times << prev_month
        end

        end_times
      end
      # rubocop: enable CodeReuse/ActiveRecord
    end
  end
end
