# frozen_string_literal: true

module Gitlab
  module SidekiqMiddleware
    module ConcurrencyLimit
      # A per-tenant share of a worker's concurrency limit, declared with
      # WorkerAttributes#concurrency_limit_scope.
      class Scope
        # Read from the application context of the code that enqueued the job, so no lookup is needed.
        CONTEXT_KEYS = {
          root_namespace: Labkit::Context.log_key(:root_namespace),
          user: Labkit::Context.log_key(Labkit::Fields::GL_USER_ID)
        }.freeze
        TYPES = CONTEXT_KEYS.keys.freeze
        # Job payload fields: the resolved scope key, and whether a resumed job has a reserved slot.
        JOB_KEY = 'concurrency_limit_scope'
        RESERVED_JOB_KEY = 'concurrency_limit_reserved'

        # Validates the arguments of WorkerAttributes#concurrency_limit_scope.
        def self.validate!(type, max_percentage, limit)
          raise ArgumentError, "Invalid concurrency limit scope: #{type.inspect}" unless TYPES.include?(type)
          raise ArgumentError, 'max_percentage or limit is required' unless max_percentage || limit
          raise ArgumentError, 'limit must be a Proc instance' if limit && !limit.is_a?(Proc)

          validate_percentage!(max_percentage) if max_percentage
        end

        def self.validate_percentage!(value)
          return if value.is_a?(Numeric) && value > 0 && value <= 1

          raise ArgumentError, "max_percentage must be a number in (0, 1], got: #{value.inspect}"
        end
        private_class_method :validate_percentage!

        # @return [Scope, nil] nil when the worker has no scope, it is turned off for the worker, or it caps nothing
        def self.for(worker_class)
          config = worker_class.try(:get_concurrency_limit_scope)
          return unless config && enabled_for?(worker_class, config[:enabled])

          scope = new(**config.except(:enabled))
          scope if scope.limited?
        end

        # Enqueue, perform and resume must agree on whether a worker is scoped, so every check is against
        # :instance only, and so must the worker's own `enabled` lambda be.
        def self.enabled_for?(worker_class, enabled)
          return false unless Feature.enabled?(:sidekiq_concurrency_limit_scope, :instance)
          return false if disabled_for_worker?(worker_class)
          return false if enabled && !enabled.call

          # Without it, track_execution_end and the stale-tracker cleanup are off too.
          Feature.enabled?(:sidekiq_concurrency_limit_middleware, :instance, type: :ops)
        end
        private_class_method :enabled_for?

        # Turns the scope off for one worker, for example during an incident, leaving its worker limit on.
        def self.disabled_for_worker?(worker_class)
          Feature.enabled?(
            :"disable_sidekiq_concurrency_limit_scope_#{worker_class.name}", # rubocop:disable Gitlab/FeatureFlagKeyDynamic -- need to check against worker name dynamically
            :instance,
            type: :worker,
            default_enabled_if_undefined: false
          )
        end
        private_class_method :disabled_for_worker?

        attr_reader :type

        def initialize(type:, max_percentage:, limit:)
          @type = type
          @max_percentage = max_percentage
          @limit = limit
        end

        # With only a `limit` of 0 or less, there is nothing to cap, so the worker stays unscoped.
        def limited?
          @max_percentage.present? || @limit.call.to_i > 0
        end

        # @return [String, nil] the tenant the job counts against, or nil when its context has none
        def key_for(job)
          value = job[CONTEXT_KEYS.fetch(type)]
          "#{type}:#{value}" if value.present?
        end

        # @return [Integer] the per-key limit, or 0 (no per-key limit) when the worker has no limit
        def limit_for(worker_limit)
          return 0 if worker_limit <= 0

          share = (worker_limit * @max_percentage).ceil if @max_percentage
          absolute = @limit&.call.to_i
          absolute = nil unless absolute.to_i > 0

          [share, absolute].compact.min || worker_limit
        end
      end
    end
  end
end
