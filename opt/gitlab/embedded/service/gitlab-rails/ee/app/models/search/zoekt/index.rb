# frozen_string_literal: true

module Search
  module Zoekt
    class Index < ApplicationRecord
      self.table_name = 'zoekt_indices'
      include NamespaceValidateable

      DEFAULT_USED_STORAGE_BYTES = 1.kilobyte.freeze
      DEFAULT_BUFFER_FACTOR = 3.0
      # Matches the `zoekt_indices.last_indexed_at` column default. An index still carrying this
      # value has never completed an indexing run, so its content age is unknown rather than old.
      NEVER_INDEXED_AT = Time.at(0).utc.freeze
      GLOBAL_BUFFER_FACTOR_CACHE_KEY = 'search/zoekt/index/global_buffer_factor'
      GLOBAL_BUFFER_FACTOR_CACHE_TTL = 1.hour
      EVICTION_STATES = %i[evicted pending_eviction].freeze
      SEARCHEABLE_STATES = %i[ready].freeze
      SHOULD_BE_DELETED_STATES = %i[orphaned pending_deletion].freeze
      STORAGE_IDEAL_PERCENT_USED = 0.6
      STORAGE_LOW_WATERMARK = 0.70
      STORAGE_HIGH_WATERMARK = 0.75
      STORAGE_CRITICAL_WATERMARK = 0.80
      # A freshly provisioned index settles at used/reserved = 1/margin, so a margin below
      # 1/STORAGE_CRITICAL_WATERMARK provisions an index that is already critical. Target the
      # ideal utilization point, plus headroom for per-namespace.
      # Declared here rather than alphabetically: it derives from STORAGE_IDEAL_PERCENT_USED.
      DYNAMIC_BUFFER_SAFETY_MARGIN = (1 / STORAGE_IDEAL_PERCENT_USED) * 1.5

      belongs_to :zoekt_enabled_namespace, inverse_of: :indices, class_name: '::Search::Zoekt::EnabledNamespace'
      belongs_to :node, foreign_key: :zoekt_node_id, inverse_of: :indices, class_name: '::Search::Zoekt::Node'
      belongs_to :replica, foreign_key: :zoekt_replica_id, inverse_of: :indices

      has_many :zoekt_repositories, foreign_key: :zoekt_index_id, inverse_of: :zoekt_index,
        class_name: '::Search::Zoekt::Repository'

      validates :metadata, json_schema: { filename: 'zoekt_indices_metadata' }

      enum :state, {
        pending: 0,
        in_progress: 1,
        initializing: 2,
        ready: 10,
        reallocating: 20,
        pending_eviction: 220,
        evicted: 225,
        orphaned: 230,
        pending_deletion: 240
      }

      enum :watermark_level, {
        healthy: 0,
        overprovisioned: 10,
        low_watermark_exceeded: 30,
        high_watermark_exceeded: 60,
        critical_watermark_exceeded: 90
      }

      scope :for_node, ->(node) do
        where(node: node)
      end

      scope :for_replica, ->(ids) { where(replica: ids) }
      scope :for_root_namespace_id, ->(root_namespace_id) do
        where(namespace_id: root_namespace_id).where.not(zoekt_enabled_namespace_id: nil)
      end

      scope :pre_ready, -> { where(state: %i[pending in_progress initializing]) }

      scope :searchable, -> do
        where(state: SEARCHEABLE_STATES)
          .joins(:zoekt_enabled_namespace)
          .where(zoekt_enabled_namespace: { search: true })
      end

      scope :for_root_namespace_id_with_search_enabled, ->(root_namespace_id) do
        for_root_namespace_id(root_namespace_id)
          .joins(:zoekt_enabled_namespace)
          .where(zoekt_enabled_namespace: { search: true })
      end

      scope :with_all_finished_repositories, -> do
        where_not_exists(Repository.uncompleted.where(Repository.arel_table[:zoekt_index_id].eq(Index.arel_table[:id])))
      end

      scope :ordered, -> { order(:id) }
      scope :ordered_by_used_storage_updated_at, -> { order(:used_storage_bytes_updated_at) }
      scope :preload_zoekt_enabled_namespace_and_namespace, -> { includes(zoekt_enabled_namespace: :namespace) }
      scope :preload_node_zoekt_enabled_namespace, -> { includes(:node, :zoekt_enabled_namespace) }
      scope :with_stale_used_storage_bytes_updated_at, -> { where('last_indexed_at >= used_storage_bytes_updated_at') }
      scope :ever_indexed, -> { where.not(last_indexed_at: NEVER_INDEXED_AT) }
      scope :with_latest_used_storage_bytes_updated_at, -> { where('last_indexed_at < used_storage_bytes_updated_at') }
      scope :should_be_marked_as_orphaned, -> do
        where(zoekt_enabled_namespace: nil).or(where(replica: nil)).where.not(state: SHOULD_BE_DELETED_STATES)
      end

      scope :should_be_pending_eviction, -> do
        critical_watermark_exceeded.where.not(state: EVICTION_STATES + SHOULD_BE_DELETED_STATES)
      end

      scope :should_be_deleted, -> do
        where(state: SHOULD_BE_DELETED_STATES)
      end

      # Indices whose data is still on the node after they lost their replica or were marked for removal.
      scope :pending_removal, -> do
        where(replica: nil).or(where(state: EVICTION_STATES + SHOULD_BE_DELETED_STATES))
      end

      scope :with_mismatched_watermark_levels, -> do
        where <<~SQL.squish
          CASE
            WHEN (used_storage_bytes / NULLIF(reserved_storage_bytes, 0)::float) < #{STORAGE_IDEAL_PERCENT_USED}
              THEN #{watermark_levels[:overprovisioned]}
            WHEN (used_storage_bytes / NULLIF(reserved_storage_bytes, 0)::float) < #{STORAGE_LOW_WATERMARK}
              THEN #{watermark_levels[:healthy]}
            WHEN (used_storage_bytes / NULLIF(reserved_storage_bytes, 0)::float) < #{STORAGE_HIGH_WATERMARK}
              THEN #{watermark_levels[:low_watermark_exceeded]}
            WHEN (used_storage_bytes / NULLIF(reserved_storage_bytes, 0)::float) < #{STORAGE_CRITICAL_WATERMARK}
              THEN #{watermark_levels[:high_watermark_exceeded]}
            ELSE #{watermark_levels[:critical_watermark_exceeded]}
          END != watermark_level
        SQL
      end

      def self.sum_reserved_storage_bytes_by_node(node_ids)
        where(zoekt_node_id: node_ids).group(:zoekt_node_id).sum(:reserved_storage_bytes)
      end

      def self.smallest_ready_id_reserving_at_least(bytes)
        ready.where(reserved_storage_bytes: bytes..).order(:reserved_storage_bytes, :id).pick(:id)
      end

      def self.largest_ready_reservations(limit:)
        ready.where(reserved_storage_bytes: 1..).order(reserved_storage_bytes: :desc, id: :asc).limit(limit)
          .pluck(:id, :reserved_storage_bytes)
      end

      # Callers combine this with `.ever_indexed`; without it a never-indexed node reports the
      # column default as though it were a real run.
      def self.newest_last_indexed_at
        maximum(:last_indexed_at)
      end

      # Ready indices to evict to free `bytes_to_free`: the smallest one that frees enough on its own, otherwise the
      # largest first, so as few namespaces as possible lose search. Indices that are not ready yet only hold a
      # placeholder `used_storage_bytes`, so evicting them frees nothing. A namespace has at most one index per node.
      #
      # @param bytes_to_free [Integer] bytes the eviction needs to free
      # @param limit [Integer] maximum number of indices to return
      # @return [Array<Array(Integer, Integer, Integer)>] namespace ID, bytes used, and replica ID
      def self.eviction_candidates(bytes_to_free:, limit:)
        evictable = ready.where.not(replica: nil)
        columns = [:namespace_id, :used_storage_bytes, :zoekt_replica_id]

        best_fit = evictable.where(used_storage_bytes: bytes_to_free..).order(:used_storage_bytes, :id).limit(1)
          .pluck(*columns)
        return best_fit if best_fit.any?

        evictable.order(used_storage_bytes: :desc, id: :asc).limit(limit).pluck(*columns)
      end

      # Computes an instance-wide buffer factor from observed Zoekt disk usage vs source repository size.
      #
      # Aggregates `used_storage_bytes` across all ready indices and divides by the total
      # `repository_size` of their root namespaces. A safety margin is applied on top.
      # Falls back to DEFAULT_BUFFER_FACTOR when no reliable data exists (new instance).
      #
      # The result is cached for GLOBAL_BUFFER_FACTOR_CACHE_TTL to avoid running the
      # aggregate query on every planning cycle.
      def self.global_buffer_factor
        Rails.cache.fetch(GLOBAL_BUFFER_FACTOR_CACHE_KEY, expires_in: GLOBAL_BUFFER_FACTOR_CACHE_TTL) do
          compute_global_buffer_factor
        end
      end

      # Performs a single bulk UPDATE for all provided records.
      # Each element of +updates+ must be a hash with keys:
      # :id, :used_storage_bytes, :used_storage_bytes_updated_at, :reserved_storage_bytes, :watermark_level (integer)
      # Uses a single SQL UPDATE ... FROM (VALUES ...) statement instead of
      # individual per-row UPDATEs, reducing 1000 DB round-trips to 1.
      def self.bulk_update_storage_bytes_and_watermark_level!(updates)
        return if updates.empty?

        conn = connection
        now_quoted = conn.quote(Time.current.iso8601(6))

        value_rows = updates.map do |u|
          "(#{conn.quote(u[:id])}::bigint, " \
            "#{conn.quote(u[:used_storage_bytes])}::bigint, " \
            "#{conn.quote(u[:used_storage_bytes_updated_at].iso8601(6))}::timestamptz, " \
            "#{conn.quote(u[:reserved_storage_bytes])}::bigint, " \
            "#{conn.quote(u[:watermark_level])}::smallint)"
        end.join(', ')

        conn.execute(<<~SQL.squish)
          UPDATE #{quoted_table_name} AS z
          SET
            used_storage_bytes             = v.used_storage_bytes,
            used_storage_bytes_updated_at  = v.used_storage_bytes_updated_at,
            reserved_storage_bytes         = v.reserved_storage_bytes,
            watermark_level                = v.watermark_level,
            updated_at                     = #{now_quoted}
          FROM (VALUES #{value_rows})
            AS v(id, used_storage_bytes, used_storage_bytes_updated_at, reserved_storage_bytes, watermark_level)
          WHERE z.id = v.id
        SQL
      end

      # Batched over enabled namespaces so no single statement reads every ready index; one cold
      # statement over all of them exceeded the statement timeout on GitLab.com.
      def self.compute_global_buffer_factor
        total_used = 0
        total_repository_size = 0

        EnabledNamespace.each_batch do |enabled_namespaces|
          sums = connection.select_one(<<~SQL.squish)
            SELECT
              SUM(per_namespace_stats.total_used) AS total_used,
              SUM(per_namespace_stats.repository_size) AS repository_size
            FROM (
              SELECT
                SUM(zoekt_indices.used_storage_bytes) AS total_used,
                MAX(namespace_root_storage_statistics.repository_size) AS repository_size
              FROM zoekt_indices
              INNER JOIN zoekt_enabled_namespaces
                ON zoekt_enabled_namespaces.id = zoekt_indices.zoekt_enabled_namespace_id
              INNER JOIN namespace_root_storage_statistics
                ON namespace_root_storage_statistics.namespace_id = zoekt_enabled_namespaces.root_namespace_id
              WHERE zoekt_enabled_namespaces.id IN (#{enabled_namespaces.select(:id).to_sql})
                AND zoekt_indices.state = #{states[:ready]}
                AND zoekt_indices.used_storage_bytes > #{DEFAULT_USED_STORAGE_BYTES}
                AND namespace_root_storage_statistics.repository_size > 0
              GROUP BY zoekt_enabled_namespaces.root_namespace_id
            ) per_namespace_stats
          SQL

          total_used += sums['total_used'].to_i
          total_repository_size += sums['repository_size'].to_i
        end

        ratio = total_used.to_f / total_repository_size if total_repository_size > 0
        return DEFAULT_BUFFER_FACTOR if ratio.nil? || ratio == 0

        ratio * DYNAMIC_BUFFER_SAFETY_MARGIN
      end
      private_class_method :compute_global_buffer_factor

      # Compute new storage values in memory without persisting.
      # Used by batch workers that collect values and then issue a single bulk UPDATE.
      # Returns a hash of attributes ready for +bulk_update_storage_bytes_and_watermark_level!+.
      def compute_storage_bytes_and_watermark_level(skip_used_storage_bytes: false, repository_size_sum: nil)
        refresh_used_storage_bytes(repository_size_sum) unless skip_used_storage_bytes
        refresh_reserved_storage_bytes
        self.watermark_level = appropriate_watermark_level

        {
          id: id,
          used_storage_bytes: used_storage_bytes,
          used_storage_bytes_updated_at: used_storage_bytes_updated_at,
          reserved_storage_bytes: reserved_storage_bytes,
          watermark_level: self.class.watermark_levels[watermark_level]
        }
      end

      def free_storage_bytes
        reserved_storage_bytes.to_i - used_storage_bytes
      end

      def should_be_deleted?
        SHOULD_BE_DELETED_STATES.include? state.to_sym
      end

      def find_or_create_repository_by_project!(identifier, project)
        zoekt_repositories.find_or_create_by!(project_identifier: identifier, project: project)
      end

      def project_namespace_id_exhaustive_range
        case [metadata['project_namespace_id_from'], metadata['project_namespace_id_to']]
        in [nil, nil]
          nil
        in [nil, id_to]
          (..id_to)
        in [id_from, nil]
          (id_from..)
        in [id_from, id_to]
          id_from..id_to
        end
      end

      def appropriate_watermark_level
        case storage_percent_used
        when 0...STORAGE_IDEAL_PERCENT_USED then :overprovisioned
        when STORAGE_IDEAL_PERCENT_USED...STORAGE_LOW_WATERMARK then :healthy
        when STORAGE_LOW_WATERMARK...STORAGE_HIGH_WATERMARK then :low_watermark_exceeded
        when STORAGE_HIGH_WATERMARK...STORAGE_CRITICAL_WATERMARK then :high_watermark_exceeded
        else
          :critical_watermark_exceeded
        end
      end

      private

      def storage_percent_used
        used_storage_bytes / reserved_storage_bytes.to_f
      end

      def refresh_used_storage_bytes(repository_size_sum = nil)
        sum_for_index = repository_size_sum || zoekt_repositories.sum(:size_bytes)
        self.used_storage_bytes = sum_for_index == 0 ? DEFAULT_USED_STORAGE_BYTES : sum_for_index
        self.used_storage_bytes_updated_at = Time.zone.now
      end

      # Allows the reduction of reserved_storage_bytes only if index is ready.
      # Always allows the possible expansion of reserved_storage_bytes.
      def refresh_reserved_storage_bytes
        # This number of bytes will put the index as the ideal storage utilization.
        ideal_reserved_storage_bytes = (used_storage_bytes / STORAGE_IDEAL_PERCENT_USED).to_i

        # Note: this will also **decrease** the reservation if the total needed is now lower.
        new_reserved_bytes = if ideal_reserved_storage_bytes > reserved_storage_bytes
                               claim_reserved_storage_bytes_from_node(ideal_reserved_storage_bytes)
                             else
                               ideal_reserved_storage_bytes
                             end

        # Do not update reserved_storage_bytes if new_reserved_bytes is less and index is not ready.
        # Case could be that index is initializing and used_storage_bytes is just building up. So do not rely on it.
        return if (new_reserved_bytes < reserved_storage_bytes) && !ready?

        self.reserved_storage_bytes = new_reserved_bytes
      end

      # Return existing reserved_storage_bytes if node does not have any unclaimed_storage_bytes.
      # If node has full availability of storage bytes asked by index, it will return the storage bytes asked by index.
      # If node has not full availability, node will return the maximum it can give to the index.
      def claim_reserved_storage_bytes_from_node(ideal_reserved_storage_bytes)
        # return existing reserved_storage_bytes, can not do anything as there is no unclaimed storage in node.
        return reserved_storage_bytes if node.unclaimed_storage_bytes <= 0

        max_reservable_storage_bytes = node.unclaimed_storage_bytes + reserved_storage_bytes.to_i
        # In case there is more requested bytes than available on the node,
        # we reserve the minimum amount that we have available.
        [ideal_reserved_storage_bytes, max_reservable_storage_bytes].min
      end
    end
  end
end
