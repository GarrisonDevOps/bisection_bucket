# frozen_string_literal: true

module API
  module Helpers
    module SidekiqConcurrencyLimitsHelpers
      def concurrency_limit_worker
        worker = ::Gitlab::SidekiqConfig.workers_without_default.find { |entry| entry.klass.name == params[:worker_class] }
        not_found!('Sidekiq worker') unless worker

        worker.klass
      end

      def concurrency_limit_service(worker)
        ::Gitlab::SidekiqMiddleware::ConcurrencyLimit::ConcurrencyLimitService.new(worker.name)
      end

      def concurrency_limit_status(worker, service)
        override = service.override_status
        class_limit = worker.configured_concurrency_limit
        enabled = Feature.enabled?(:sidekiq_concurrency_limit_middleware, Feature.current_request, type: :ops)
        disabled_for_worker = Feature.enabled?(
          :"disable_sidekiq_concurrency_limit_middleware_#{worker.name}", # rubocop:disable Gitlab/FeatureFlagKeyDynamic -- Existing per-worker bypass flag
          Feature.current_request, type: :worker, default_enabled_if_undefined: false)
        # Shard-derived defaults cannot be calculated accurately in a web process. With the
        # calculation flag off, WorkerAttributes#calculate_default_limit_from_max_percentage
        # returns 0 in every process, so the default is known.
        default_requires_shard_context = class_limit.nil? && Feature.enabled?(
          :sidekiq_concurrency_limit_default_calculation, Feature.current_request, type: :ops)
        default_limit = default_requires_shard_context ? nil : class_limit.to_i
        adaptive_limit = service.stored_adaptive_limit
        effective_limit = if !enabled || disabled_for_worker
                            0
                          elsif default_limit && default_limit < 0
                            default_limit
                          else
                            override[:limit] || adaptive_limit || default_limit
                          end

        {
          worker_class: worker.name,
          class_limit: class_limit,
          effective_limit: effective_limit,
          adaptive_limit: adaptive_limit,
          default_limit_requires_shard_context: default_requires_shard_context,
          middleware_enabled: enabled,
          disabled_for_worker: disabled_for_worker,
          override_limit: override[:limit],
          override_ttl: override[:ttl],
          running_jobs: service.concurrent_worker_count,
          deferred_jobs: service.queue_size
        }
      end

      def log_concurrency_limit_override(worker, action, previous, current)
        Gitlab::AppLogger.info(
          Labkit::Fields::CLASS_NAME => 'API::Admin::Sidekiq',
          message: 'Sidekiq concurrency limit override changed',
          worker_class: worker.name,
          action: action,
          Labkit::Fields::GL_USER_ID => current_user.id,
          previous_override: previous,
          override: current
        )
      end
    end
  end
end
