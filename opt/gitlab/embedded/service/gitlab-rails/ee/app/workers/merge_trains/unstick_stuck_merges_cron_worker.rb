# frozen_string_literal: true

module MergeTrains
  class UnstickStuckMergesCronWorker
    include ApplicationWorker
    include CronjobQueue # rubocop:disable Scalability/CronWorkerContext -- No metadata needed as it's called from cronjobs
    include Gitlab::ExclusiveLeaseHelpers

    data_consistency :sticky
    feature_category :merge_trains
    urgency :low
    idempotent!
    defer_on_database_health_signal :gitlab_main, [], 5.minutes

    LEASE_TTL = 30.minutes

    def perform
      enqueued = Set.new
      in_lock(lease_key, ttl: LEASE_TTL, retries: 0) do
        ::MergeTrains::Car.stuck_cars.each_batch do |batch|
          batch.each do |car|
            key = [car.target_project_id, car.target_branch]
            next if enqueued.include?(key)

            MergeTrains::RefreshWorker.perform_async(car.target_project_id, car.target_branch)
            enqueued.add(key)
          end
        end
      end
    end

    private

    def lease_key
      "merge_trains:unstick_stuck_merges"
    end
  end
end
