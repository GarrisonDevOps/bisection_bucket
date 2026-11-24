# frozen_string_literal: true

module Gitlab
  module SidekiqMiddleware
    module ConcurrencyLimit
      # Free-slot mode, opted into per worker with the `sidekiq_concurrency_limit_use_free_slots_<WorkerName>`
      # flag: a new job runs whenever the worker is below its limit, even while deferred jobs wait, instead
      # of joining the deferred list behind them. Resumed jobs reserve their slot, so the list is not starved.
      module FreeSlots
        # Once the oldest deferred job has waited this long, new jobs leave RESUMER_RESERVE_PERCENTAGE of
        # the limit free for ConcurrencyLimit::ResumeWorker, so the list keeps draining under sustained load.
        HEAD_AGE_CAP = 5.minutes
        RESUMER_RESERVE_PERCENTAGE = 0.1

        # Enqueue, perform and resume must agree on the mode, so the check is against :instance only.
        # The per-worker flag comes first: it is off for almost every worker, so the flag-off path
        # costs one lookup per job.
        def self.enabled_for?(worker_class)
          return false unless worker_class

          return false unless Feature.enabled?(
            :"sidekiq_concurrency_limit_use_free_slots_#{worker_class.name}", # rubocop:disable Gitlab/FeatureFlagKeyDynamic -- need to check against worker name dynamically
            :instance,
            type: :worker,
            default_enabled_if_undefined: false
          )

          Feature.enabled?(:sidekiq_concurrency_limit_middleware, :instance, type: :ops)
        end

        # @param limit [Integer] the worker's limit
        # @param head_buffered_at [Float, nil] when the oldest deferred job was deferred, nil for an empty list
        # @return [Integer] the limit new jobs are admitted against
        def self.admission_limit(limit, head_buffered_at)
          return limit if limit <= 0
          return limit unless head_buffered_at && head_buffered_at <= HEAD_AGE_CAP.ago.to_f

          limit - [(limit * RESUMER_RESERVE_PERCENTAGE).ceil, 1].max
        end
      end
    end
  end
end
