# frozen_string_literal: true

module Search
  module Zoekt
    class RolloutService
      include Gitlab::Loggable

      CLEANUP_BATCH_SIZE = 1_000

      DEFAULT_OPTIONS = {
        max_indices_per_replica: MAX_INDICES_PER_REPLICA,
        dry_run: true,
        batch_size: 128
      }.freeze

      Result = Data.define(:message, :changes, :re_enqueue)

      def self.execute(**kwargs)
        new(**kwargs).execute
      end

      attr_reader :max_indices_per_replica, :batch_size, :dry_run

      def initialize(**kwargs)
        options = DEFAULT_OPTIONS.merge(kwargs)
        @max_indices_per_replica = options.fetch(:max_indices_per_replica)
        @dry_run = options.fetch(:dry_run)
        @batch_size = options.fetch(:batch_size)
      end

      def execute
        # Cleanup replicas without indices before processing
        cleanup_replicas_without_indices unless dry_run

        resource_pool = ::Search::Zoekt::SelectionService.execute(max_batch_size: batch_size)
        return Result.new('No enabled namespaces found', {}, false) if resource_pool.enabled_namespaces.empty?
        return Result.new('No available nodes found', {}, false) if resource_pool.nodes.empty?

        plan = ::Search::Zoekt::PlanningService.plan(
          enabled_namespaces: resource_pool.enabled_namespaces,
          nodes: resource_pool.nodes,
          max_indices_per_replica: max_indices_per_replica
        )
        logger.info(build_structured_payload(**{ zoekt_rollout_plan: ::Gitlab::Json.safe_parse(plan.to_json) }))
        return Result.new('Skipping execution of changes because of dry run', {}, false) if dry_run

        record_planning_failures(plan[:failures])
        changes = ::Search::Zoekt::ProvisioningService.execute(plan)
        result(changes)
      end

      private

      # Planning logs one error per project that does not fit, so count each namespace once.
      def record_planning_failures(failures)
        capacity_error_types = ::Search::Zoekt::PlanningService::Plan::CAPACITY_ERROR_TYPES

        failures.each do |failure|
          next unless failure[:errors].any? { |error| capacity_error_types.include?(error[:type]) }

          ::Gitlab::Metrics::ZoektRolloutSlis.increment_planning_failure
        end
      end

      def cleanup_replicas_without_indices
        deleted_total = 0

        # Delete all replicas without indices in batches
        ::Search::Zoekt::Replica.without_indices.each_batch(of: CLEANUP_BATCH_SIZE) do |batch|
          deleted_total += batch.delete_all
        end

        return if deleted_total == 0

        logger.info(message: 'Deleted Zoekt replicas without indices', total_deleted_replicas: deleted_total)
      end

      def logger
        @logger ||= ::Search::Zoekt::Logger.build
      end

      def result(changes = {})
        success = changes[:success]&.any?
        errors = changes[:errors]&.any?

        resource_pool = SelectionService.execute(max_batch_size: batch_size)
        should_re_enqueue = resource_pool.enabled_namespaces.any? && resource_pool.nodes.any?

        message, re_enqueue = if success && errors
                                ['Batch is completed with partial success', should_re_enqueue]
                              elsif errors
                                ['Batch is completed with failure', false]
                              elsif success
                                ['Batch is completed with success', should_re_enqueue]
                              else
                                ['Batch is completed without changes', should_re_enqueue]
                              end

        Result.new(message, changes, re_enqueue)
      end
    end
  end
end
