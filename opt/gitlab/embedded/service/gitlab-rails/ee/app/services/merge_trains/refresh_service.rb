# frozen_string_literal: true

module MergeTrains
  # This class is to refresh all merge requests on the merge train that
  # the given merge request belongs to.
  #
  # It performs a sequential update on all merge requests on the train.
  # Multiple runs with the same project and branch should not take place concurrently
  # NOTE: To prevent concurrent refreshes, two locking mechanisms are in place:
  # 1. `MergeTrains::RefreshWorker` deduplicates via `deduplicate :until_executed, if_deduplicated: :reschedule_once`
  # 2. This service holds an `ExclusiveLeaseGuard` (scoped to project + branch) and renews it per car,
  #    guarding against cases where a refresh outlives the worker's 10-minute deduplication TTL.
  class RefreshService
    include ::ExclusiveLeaseGuard

    DEFAULT_CONCURRENCY = 20
    LEASE_TIMEOUT = 10.minutes
    # Checked between cars, so it leaves room for the last car within the lease and the
    # worker's deduplication TTL; events arriving mid-pass are then rescheduled, not dropped.
    TIME_BUDGET = 5.minutes

    def initialize(target_project_id, target_branch)
      @target_project_id = target_project_id
      @target_branch = target_branch
    end

    def execute
      response = try_obtain_lease do
        require_next_recreate = false
        acted = false
        deferred = false
        cars_processed = 0
        train = MergeTrains::Train.new(@target_project_id, @target_branch)
        deadline = Gitlab::Metrics::System.monotonic_time + TIME_BUDGET

        train.refreshable_cars(limit: concurrency_limit).each do |car|
          break unless renew_lease!

          # Only yield after real work, so a slow walk over idle cars cannot keep
          # every pass from reaching the cars behind them.
          if acted && Gitlab::Metrics::System.monotonic_time >= deadline && time_budget_enabled?
            defer_remaining_cars(train, car, require_next_recreate)
            deferred = true
            break
          end

          result = MergeTrains::RefreshMergeRequestService
            .new(car.target_project, car.user, require_recreate: require_next_recreate)
            .execute(car.merge_request)

          cars_processed += 1
          require_next_recreate = result[:status] == :error || result[:pipeline_created]
          acted ||= require_next_recreate || car.merge_request.merged?
        end

        ServiceResponse.success(payload: { cars_processed: cars_processed, deferred: deferred })
      end

      response || ServiceResponse.error(message: 'Another refresh holds the lease', reason: :lease_taken)
    end

    private

    # The next pass starts again from the first car, so a pending recreate must
    # be stored on the car rather than carried in memory.
    def defer_remaining_cars(train, next_car, require_recreate)
      next_car.outdate_pipeline if require_recreate
      train.refresh_async
    end

    def time_budget_enabled?
      Feature.enabled?(:merge_trains_refresh_time_budget, Project.actor_from_id(@target_project_id))
    end

    def lease_timeout
      LEASE_TIMEOUT
    end

    def lease_key
      "merge_trains:refresh:#{@target_project_id}:#{@target_branch}"
    end

    def concurrency_limit
      project = Project.find_by_id(@target_project_id)
      return DEFAULT_CONCURRENCY unless project

      plan_limit = project.actual_limits.max_pipelines_per_merge_train
      project_limit = project.ci_cd_settings&.max_pipelines_per_merge_train

      if project_limit.present?
        [plan_limit, project_limit].min
      else
        plan_limit
      end
    end
  end
end
