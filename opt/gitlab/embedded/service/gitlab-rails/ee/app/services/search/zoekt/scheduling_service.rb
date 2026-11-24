# frozen_string_literal: true

module Search
  module Zoekt
    class SchedulingService
      include Gitlab::Loggable
      include Gitlab::Scheduling::TaskExecutor

      NODE_PROCESSING_LIMIT = 100
      # How long a node must stay over the high watermark before eviction, so temporary disk usage, such as
      # during a reindex, does not trigger it. A node over the critical watermark is evicted from right away.
      EVICTION_SUSTAINED_DURATION = 8.hours
      EVICTION_MAX_NAMESPACES = 5_000
      EVICTION_LOGGED_NAMESPACES = 100

      CONFIG = {
        force_update_overprovisioned_index: {
          if: -> { Index.overprovisioned.ready.with_latest_used_storage_bytes_updated_at.exists? },
          dispatch: { event: ForceUpdateOverprovisionedIndexEvent }
        },
        indices_to_evict_check: {
          if: -> { Index.pending_eviction.exists? },
          dispatch: { event: IndexToEvictEvent }
        },
        index_mismatched_watermark_check: {
          period: 10.minutes,
          if: -> { Search::Zoekt::Index.with_mismatched_watermark_levels.exists? },
          execute: -> {
            info(
              :index_mismatched_watermark_check,
              message: "Detected indices with mismatched watermarks",
              count: Search::Zoekt::Index.with_mismatched_watermark_levels.count
            )
          }
        },
        index_should_be_marked_as_orphaned_check: {
          if: -> { Index.should_be_marked_as_orphaned.exists? },
          dispatch: { event: OrphanedIndexEvent }
        },
        index_should_be_marked_as_pending_eviction_check: {
          if: -> { Index.should_be_pending_eviction.exists? },
          dispatch: { event: IndexMarkPendingEvictionEvent }
        },
        index_to_delete_check: {
          if: -> { Index.should_be_deleted.exists? },
          dispatch: { event: IndexMarkedAsToDeleteEvent }
        },
        lost_nodes_check: {
          period: 10.minutes,
          if: -> {
            !Rails.env.development? &&
              Node.marking_lost_enabled? &&
              Node.for_search.lost.exists? &&
              Node.for_search.online.exists?
          },
          dispatch: {
            event: LostNodeEvent,
            data: -> {
              { zoekt_node_id: Node.for_search.lost.limit(1).select(:id).last.id }
            }
          }
        },
        mark_indices_as_ready: {
          if: -> { Index.initializing.with_all_finished_repositories.exists? },
          dispatch: { event: IndexMarkedAsReadyEvent }
        },
        remove_expired_subscriptions: {
          period: 1.day,
          if: -> {
            !Rails.env.development? && ::Gitlab::Saas.feature_available?(:exact_code_search)
          },
          execute: -> { EnabledNamespace.destroy_namespaces_with_expired_subscriptions! }
        },
        repo_should_be_marked_as_orphaned_check: {
          period: 10.minutes,
          if: -> { Search::Zoekt::Repository.should_be_marked_as_orphaned.exists? },
          dispatch: { event: OrphanedRepoEvent }
        },
        repo_to_index_check: {
          if: -> { Repository.should_be_indexed.exists? },
          dispatch: { event: RepoToIndexEvent }
        },
        repo_to_reindex_check: {
          if: -> { Repository.should_be_reindexed.exists? },
          execute: -> {
            node_ids = Node.needs_reindex(NODE_PROCESSING_LIMIT).map(&:id)

            # Emit one event per node for parallel processing
            node_ids.each do |node_id|
              dispatch RepoToReindexEvent do
                { zoekt_node_id: node_id }
              end
            end

            if node_ids.any?
              info(
                :emit_repo_to_reindex_events,
                message: 'Emitted per-node reindex events',
                node_count: node_ids.count,
                node_ids: node_ids
              )
            end
          }
        },
        retry_failed_repos: {
          period: 1.day,
          if: -> { Repository.failed.exists? },
          dispatch: { event: RetryFailedReposEvent }
        },
        task_claim_expired_check: {
          period: 10.minutes,
          if: -> { Task.with_expired_claim.exists? },
          dispatch: { event: TaskClaimExpiredEvent }
        },
        repo_to_delete_check: {
          if: -> { ::Search::Zoekt::Repository.should_be_deleted.exists? },
          dispatch: { event: RepoMarkedAsToDeleteEvent }
        },
        update_index_used_storage_bytes: {
          if: -> { Index.with_stale_used_storage_bytes_updated_at.exists? },
          dispatch: { event: UpdateIndexUsedStorageBytesEvent }
        },
        update_replica_states: {
          execute: -> { ReplicaStateService.execute }
        },
        saas_rollout: {
          period: 2.hours,
          if: -> { ::Gitlab::Saas.feature_available?(:exact_code_search) },
          dispatch: { event: SaasRolloutEvent }
        }
      }.freeze

      TASKS = (%i[
        auto_index_self_managed
        eviction
        initial_indexing
        node_with_negative_unclaimed_storage_bytes_check
        update_index_used_bytes
      ] + CONFIG.keys).freeze

      attr_reader :task

      def self.execute!(task)
        execute(task, without_cache: true)
      end

      def self.execute(task, without_cache: false)
        instance = new(task)

        Gitlab::Redis::SharedState.with { |r| r.del(instance.cache_key) } if without_cache

        instance.execute
      end

      def initialize(task)
        @task = task.to_sym
      end

      def execute
        raise ArgumentError, "Unknown task: #{task.inspect}" unless TASKS.include?(task)

        if CONFIG.key?(task)
          execute_config_task(task)
        elsif respond_to?(task, true)
          send(task) # rubocop:disable GitlabSecurity/PublicSend -- We control the list of tasks in the source code
        else
          raise NotImplementedError, "Task #{task} is not implemented."
        end
      end

      def cache_period
        return unless CONFIG.key?(task)

        CONFIG.dig(task, :period)
      end

      private

      def execute_config_task(task_name)
        config = CONFIG[task_name]
        super(task_name, config)
      end

      def logger
        @logger ||= ::Search::Zoekt::Logger.build
      end

      def info(task, **payload)
        logger.info(build_structured_payload(**payload.merge(task: task)))
      end

      # An initial implementation of eviction logic. For now, it's a .com-only task
      def eviction
        return false unless ::Gitlab::Saas.feature_available?(:exact_code_search)

        execute_every 5.minutes do
          next evict_from_overfull_nodes if Feature.enabled?(:zoekt_node_eviction_safeguards, :instance)

          nodes = ::Search::Zoekt::Node.for_search.online.find_each.to_a
          over_watermark_nodes = nodes.select(&:watermark_exceeded_high?)

          break if over_watermark_nodes.empty?

          info(:eviction, message: 'Detected nodes over watermark',
            watermark_limit_high: ::Search::Zoekt::Node::WATERMARK_LIMIT_HIGH,
            count: over_watermark_nodes.count)

          over_watermark_nodes.each do |node|
            sizes = {}

            node.indices.each_batch do |batch|
              scope = Namespace.includes(:root_storage_statistics) # rubocop:disable CodeReuse/ActiveRecord -- this is a temporary incident mitigation task
                               .by_parent(nil)
                               .id_in(batch.select(:namespace_id))

              scope.each do |group|
                sizes[group.id] = group.root_storage_statistics&.repository_size || 0
              end
            end

            sorted = sizes.to_a.sort_by { |_k, v| v }

            namespaces_to_move = []
            total_repository_size = 0
            node_original_used_bytes = node.used_bytes
            sorted.each do |namespace_id, repository_size|
              node.used_bytes -= repository_size
              namespaces_to_move << namespace_id
              total_repository_size += repository_size

              break unless node.watermark_exceeded_low?
            end

            unassign_namespaces_from_node(node, namespaces_to_move, node_original_used_bytes, total_repository_size)
          end
        end
      end

      def unassign_namespaces_from_node(node, namespaces_to_move, node_original_used_bytes, total_repository_size)
        return if namespaces_to_move.empty?

        info(:eviction, message: 'Unassigning namespaces from node',
          watermark_limit_high: ::Search::Zoekt::Node::WATERMARK_LIMIT_HIGH,
          count: namespaces_to_move.count,
          node_used_bytes: node_original_used_bytes,
          node_expected_used_bytes: node.used_bytes,
          total_repository_size: total_repository_size,
          meta: node.metadata_json
        )

        namespaces_to_move.each_slice(100) do |namespace_ids|
          ::Search::Zoekt::EnabledNamespace.for_root_namespace_id(namespace_ids).update_last_used_storage_bytes!

          ::Search::Zoekt::Replica.for_namespace(namespace_ids).each_batch do |batch|
            batch.delete_all
          end
        end
      end

      def evict_from_overfull_nodes
        cooldown_node_ids = ::Search::Zoekt::NodeEvictionState.cooldown_node_ids

        ::Search::Zoekt::Node.for_search.online.find_each do |node|
          next end_cooldown_once_freed(node) if cooldown_node_ids.include?(node.id)

          unless node.watermark_exceeded_high?
            ::Search::Zoekt::NodeEvictionState.clear_over_watermark(node)
            next
          end

          evict_from_node(node) if over_watermark_long_enough?(node)
        end
      end

      # The node's reported disk usage only drops once its indices pending removal are gone, so it keeps its
      # cooldown until none are left, whatever removed them, or for at most 12 hours. It is not evicted from in the
      # run that ends the cooldown either, which gives the node time to report its freed space.
      def end_cooldown_once_freed(node)
        return if node.indices.pending_removal.exists?

        ::Search::Zoekt::NodeEvictionState.end_cooldown(node)
      end

      def over_watermark_long_enough?(node)
        over_watermark_since = ::Search::Zoekt::NodeEvictionState.record_over_watermark(node)
        return true if node.watermark_exceeded_critical? || over_watermark_since <= EVICTION_SUSTAINED_DURATION.ago

        # Logged on every run, so a restarted waiting period shows up as a later over_watermark_since.
        info(:eviction, message: 'Waiting to evict from node over watermark',
          watermark_limit_high: ::Search::Zoekt::Node::WATERMARK_LIMIT_HIGH,
          over_watermark_since: over_watermark_since.iso8601,
          meta: node.metadata_json
        )

        false
      end

      def evict_from_node(node)
        node_used_bytes = node.used_bytes
        # Before the loop below lowers node.used_bytes to the expected value.
        node_meta = node.metadata_json
        namespace_ids = []
        replica_ids = []
        evicted_namespaces = []
        evicted_storage_bytes = 0
        # Enough to take the node strictly below the low watermark, which is where the loop below stops.
        bytes_to_free = node.used_bytes - (::Search::Zoekt::Node::WATERMARK_LIMIT_LOW * node.total_bytes).floor + 1
        candidates = node.indices.eviction_candidates(bytes_to_free: bytes_to_free, limit: EVICTION_MAX_NAMESPACES)

        candidates.each do |namespace_id, used_bytes, replica_id|
          namespace_ids << namespace_id
          replica_ids << replica_id
          evicted_namespaces << { namespace_id: namespace_id, used_storage_bytes: used_bytes }
          evicted_storage_bytes += used_bytes
          node.used_bytes -= used_bytes

          break unless node.watermark_exceeded_low?
        end

        if namespace_ids.empty?
          # Logged on every run, so a node that is due for eviction but has no ready index with a replica is not silent.
          info(:eviction, message: 'No eviction candidates on node over watermark',
            watermark_limit_high: ::Search::Zoekt::Node::WATERMARK_LIMIT_HIGH,
            meta: node_meta
          )

          return
        end

        info(:eviction, message: 'Evicting namespaces from node',
          watermark_limit_high: ::Search::Zoekt::Node::WATERMARK_LIMIT_HIGH,
          count: namespace_ids.count,
          node_used_bytes: node_used_bytes,
          node_expected_used_bytes: node.used_bytes,
          evicted_storage_bytes: evicted_storage_bytes,
          # Largest first evicts few namespaces, so they can be followed until a replica is ready again.
          evicted_namespaces: evicted_namespaces.first(EVICTION_LOGGED_NAMESPACES),
          meta: node_meta
        )

        namespace_ids.each_slice(100) do |ids|
          ::Search::Zoekt::EnabledNamespace.for_root_namespace_id(ids).update_last_used_storage_bytes!
        end

        # Only the replicas with an index on this node; other replicas of the namespace keep serving search.
        # The foreign key nulls their indices' zoekt_replica_id, so they are pending_removal and hold the cooldown.
        replica_ids.uniq.each_slice(100) { |ids| ::Search::Zoekt::Replica.id_in(ids).delete_all }

        ::Search::Zoekt::NodeEvictionState.start_cooldown(node)
      end

      def node_with_negative_unclaimed_storage_bytes_check
        execute_every 1.hour do
          Search::Zoekt::Node.for_search.negative_unclaimed_storage_bytes.each_batch do |batch|
            dispatch NodeWithNegativeUnclaimedStorageEvent do
              { node_ids: batch.pluck_primary_key }
            end
          end
        end
      end

      def initial_indexing
        nodes_to_process = Search::Zoekt::Node.for_search.online.with_pending_indices
        limit = ::Search::Zoekt::Settings.initial_indexing_limit

        nodes_to_process.find_each do |node|
          node.indices.pending.ordered.limit(limit).each do |index|
            dispatch InitialIndexingEvent do
              { index_id: index.id }
            end
          end
        end
      end

      # This task does not need to run on .com
      def auto_index_self_managed
        return if Gitlab::Saas.feature_available?(:exact_code_search)
        return unless Gitlab::CurrentSettings.zoekt_auto_index_root_namespace?

        Namespace.root_namespaces_without_zoekt_enabled_namespace.each_batch do |batch|
          data = batch.pluck_primary_key.map { |id| { root_namespace_id: id } }
          Search::Zoekt::EnabledNamespace.insert_all(data)
        end
      end

      # This task name is deprecated
      def update_index_used_bytes; end

      # Publishes an event to the event store if the given condition is met.
      #
      # Example usage:
      # dispatch RepoMarkedAsToDeleteEvent, if: -> { Search::Zoekt::Repository.should_be_deleted.exists? }
      # dispatch RepoToIndexEvent # will always be published
      # dispatch RepoToIndexEvent, if: -> { false } # will never be published
      # dispatch RepoToIndexEvent do # optional: if given a block, it will pass the return value as data to event store
      #   { id: 123, description: "data to dispatch" }
      # end
      def dispatch(event, **kwargs)
        if kwargs[:if].present? && !kwargs[:if].call
          logger.info(build_structured_payload(task: task, message: 'Nothing to dispatch'))
          return false
        end

        data = block_given? ? yield : {}

        Gitlab::EventStore.publish(event.new(data: data))
      end
    end
  end
end
