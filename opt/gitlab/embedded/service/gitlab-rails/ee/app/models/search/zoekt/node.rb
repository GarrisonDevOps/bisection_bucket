# frozen_string_literal: true

module Search
  module Zoekt
    class Node < ApplicationRecord
      self.table_name = 'zoekt_nodes'
      include FromUnion

      DEFAULT_CONCURRENCY_LIMIT = 20
      MAX_CONCURRENCY_LIMIT = 200
      ONLINE_DURATION_THRESHOLD = 30.seconds
      WATERMARK_LIMIT_LOW = 0.6
      WATERMARK_LIMIT_HIGH = Rails.env.development? ? 0.98 : 0.75
      WATERMARK_LIMIT_CRITICAL = Rails.env.development? ? 0.99 : 0.85
      TASK_PULL_FREQUENCY_DEFAULT = '5s'
      TASK_PULL_FREQUENCY_INCREASED = '500ms'
      DEBOUNCE_DELAY = 5.seconds
      VERSION_CHECK_CACHE_TTL = 10.minutes
      MMAP_USAGE_WARNING_RATIO = 0.80
      MMAP_USAGE_CRITICAL_RATIO = 0.95

      before_save :set_usable_storage_bytes

      UNCLAIMED_STORAGE_BYTES_FORMULA = <<~SQL
        (zoekt_nodes.usable_storage_bytes - COALESCE(reserved_storage_bytes_total, 0))
      SQL

      SERVICES = {
        zoekt: 0
      }.freeze

      has_many :indices,
        foreign_key: :zoekt_node_id, inverse_of: :node, class_name: '::Search::Zoekt::Index'
      has_many :enabled_namespaces,
        through: :indices, source: :zoekt_enabled_namespace, class_name: '::Search::Zoekt::EnabledNamespace'
      has_many :tasks,
        foreign_key: :zoekt_node_id, inverse_of: :node, class_name: '::Search::Zoekt::Task'
      has_many :zoekt_repositories,
        through: :indices, source: :zoekt_repositories, class_name: '::Search::Zoekt::Repository'

      validates :index_base_url, presence: true
      validates :search_base_url, presence: true
      validates :uuid, presence: true, uniqueness: true
      validates :last_seen_at, presence: true
      validates :indexed_bytes, presence: true
      validates :used_bytes, presence: true
      validates :total_bytes, presence: true
      validates :metadata, json_schema: { filename: 'zoekt_node_metadata', size_limit: 2.kilobytes }
      validates :usable_storage_bytes, presence: true, numericality: { only_integer: true }
      validates :schema_version, presence: true
      validate :valid_services

      attribute :metadata, ::Gitlab::Database::Type::IndifferentJsonb.new # for indifferent access

      scope :by_name, ->(*names) { where("metadata->>'name' IN (?)", names) }
      scope :lost, -> {
        threshold = ::Search::Zoekt::Settings.lost_node_threshold

        if threshold
          where(last_seen_at: ...threshold.ago)
        else
          none
        end
      }
      scope :online, -> { where(last_seen_at: ONLINE_DURATION_THRESHOLD.ago..) }
      scope :offline, -> { where(last_seen_at: ...ONLINE_DURATION_THRESHOLD.ago) }
      scope :searchable_for_project, ->(project) do
        searchable.joins(:zoekt_repositories)
                  .merge(Repository.searchable)
                  .where(zoekt_repositories: { project: project })
      end
      scope :with_pending_indices, -> do
        where_exists(::Search::Zoekt::Index.pending.where('zoekt_indices.zoekt_node_id = zoekt_nodes.id'))
      end
      scope :with_reserved_bytes, -> do
        node_ids_with_bytes = ::Search::Zoekt::Node.from_union([
          ::Search::Zoekt::Index.select(0, :zoekt_node_id, 'sum(reserved_storage_bytes) as reserved_bytes')
            .group(:zoekt_node_id)
        ]).select(:zoekt_node_id, 'sum(reserved_bytes) as reserved_storage_bytes_total').group(:zoekt_node_id)

        joins("LEFT OUTER JOIN (#{node_ids_with_bytes.to_sql}) reserved_bytes ON " \
          "zoekt_nodes.id=reserved_bytes.zoekt_node_id")
      end
      scope :with_positive_unclaimed_storage_bytes, -> do
        sql = <<~SQL
          zoekt_nodes.*, #{UNCLAIMED_STORAGE_BYTES_FORMULA} AS unclaimed_storage_bytes
        SQL
        with_reserved_bytes.where("#{UNCLAIMED_STORAGE_BYTES_FORMULA} > 0").select(sql)
      end
      scope :order_by_unclaimed_space_desc, -> do
        with_positive_unclaimed_storage_bytes.order('unclaimed_storage_bytes DESC')
      end
      scope :negative_unclaimed_storage_bytes, -> do
        with_reserved_bytes.where("#{UNCLAIMED_STORAGE_BYTES_FORMULA} < 0")
      end
      scope :with_service, ->(service) { where("? = ANY(services)", SERVICES.fetch(service)) }
      scope :for_search, -> { with_service(:zoekt) }

      scope :available_for_search_indexing, -> do
        for_search.online.order_by_unclaimed_space_desc
      end

      def self.find_or_initialize_by_task_request(params)
        params = params.with_indifferent_access

        find_or_initialize_by(uuid: params.fetch(:uuid)).tap do |node|
          # Note: if zoekt node makes task_request with a different `node.url`,
          # we will respect that and make change here.
          node.index_base_url = params.fetch('node.url')
          node.search_base_url = params['node.search_url'] || params.fetch('node.url')

          node.last_seen_at = Time.zone.now
          node.total_bytes = params.fetch('disk.all')
          node.indexed_bytes = params['disk.indexed'] if params['disk.indexed'].present?
          node.used_bytes = params.fetch('disk.used')
          node.schema_version = params['node.schema_version'] if params['node.schema_version'].present?
          node.assign_metadata(params)

          if params['node.services'].present?
            node.services = params['node.services'].filter_map { |service| SERVICES[service.to_sym] }
          end
        end
      end

      def self.marking_lost_enabled?
        return false if Gitlab::CurrentSettings.zoekt_indexing_paused?
        return false unless Gitlab::CurrentSettings.zoekt_indexing_enabled?
        return false unless ::Search::Zoekt::Settings.lost_node_threshold.present?

        true
      end

      def self.maximum_zoekt_schema_version
        online.maximum(:schema_version)
      end

      def self.searchable
        return online unless ::Search::Zoekt::ProcessHealth.active?

        all_online = online.to_a
        return none if all_online.empty?

        healthy = all_online.reject { |node| ::Search::Zoekt::ProcessHealth.unhealthy?(node) }

        if healthy.empty?
          log_cascade_failure_fallback(all_online)
          return online
        end

        id_in(healthy.map(&:id))
      end

      def self.log_cascade_failure_fallback(online_nodes)
        ::Search::Zoekt::Logger.build.warn(
          Labkit::Fields::CLASS_NAME => name,
          message: 'Zoekt cascade-failure fallback: all online nodes flagged unhealthy, serving from .online',
          online_node_count: online_nodes.size,
          online_node_ids: online_nodes.map(&:id)
        )
      end

      private_class_method :log_cascade_failure_fallback

      # Returns the mmap usage level for the given current/max mmap counts.
      # Compares the raw ratio (current/max) against fraction thresholds.
      #
      # @param mmap_current [Integer] current mmap count
      # @param mmap_max [Integer] maximum mmap count
      # @return [Symbol] :ok, :warning, or :critical
      def self.mmap_usage_level(mmap_current, mmap_max)
        return :ok if mmap_max.to_i <= 0

        ratio = mmap_current.to_f / mmap_max

        if ratio >= MMAP_USAGE_CRITICAL_RATIO
          :critical
        elsif ratio >= MMAP_USAGE_WARNING_RATIO
          :warning
        else
          :ok
        end
      end

      # Returns true if all online search nodes are running a version >= the given version string.
      # Result is cached for VERSION_CHECK_CACHE_TTL to avoid repeated DB queries on every search request.
      # Nodes without a reported version are treated as not supporting the feature.
      def self.all_at_least_version?(version)
        Rails.cache.fetch(['zoekt_node_all_at_least_version', version], expires_in: VERSION_CHECK_CACHE_TTL) do
          all_at_least_version_uncached?(version)
        end
      end

      # Uncached version of all_at_least_version? - queries the DB directly.
      # Version strings may include a date prefix, a leading "v", and/or a git commit suffix, e.g.:
      #   "2026.02.27-v1.9.0-62-g6229205" -> "1.9.0"
      #   "2026.02.18-v1.8.0"             -> "1.8.0"
      #   "v1.8.0"                        -> "1.8.0"
      #   "1.8.0"                         -> "1.8.0"
      def self.all_at_least_version_uncached?(version)
        required = Gem::Version.new(version)

        for_search.online.all? do |node|
          raw = node.metadata['version'].presence
          next false unless raw

          # Match MAJOR.MINOR.PATCH anchored after "-v" (date-prefixed builds) or a
          # leading optional "v" (plain semver). This ignores git commit suffixes.
          match = raw.match(/-v(\d+\.\d+\.\d+)/) || raw.match(/\Av?(\d+\.\d+\.\d+)/)
          next false unless match

          Gem::Version.new(match[1]) >= required
        end
      end
      private_class_method :all_at_least_version_uncached?

      # @return [Array<Zoekt::Node>] nodes where at least one repository is ready
      # and has a schema_version less than the node's schema_version.
      def self.needs_reindex(limit = nil)
        nodes = []
        online.each do |node|
          nodes << node if node.zoekt_repositories.ready.schema_version_less_than(node.schema_version).exists?
          return nodes if limit.present? && nodes.count >= limit
        end
        nodes
      end

      # Returns a hash mapping replica IDs to their associated nodes for an enabled namespace
      # The caller is responsible for scoping nodes appropriately (e.g., .for_search.online)
      #
      # @param enabled_namespace [Search::Zoekt::EnabledNamespace] The enabled namespace to fetch replica nodes for
      # @return [Hash<Integer, Array<Node>>] Hash of replica_id => [nodes]
      def self.replica_map_for_enabled_namespace(enabled_namespace)
        replicas = enabled_namespace.replicas.ready.preload_nodes

        # Fetch all nodes for the given replicas in a single query
        nodes_with_replica_ids = joins(:indices)
            .where(zoekt_indices: { zoekt_replica_id: replicas.select(:id) })
            .select('zoekt_nodes.*, zoekt_indices.zoekt_replica_id')
            .distinct

        # Group nodes by replica_id
        nodes_with_replica_ids.each_with_object(Hash.new { |h, k| h[k] = [] }) do |node, hash|
          hash[node.zoekt_replica_id] << node
        end
      end

      def concurrency_limit
        override = metadata['concurrency_override'].to_i
        return override if override > 0

        calculated_limit = (metadata['concurrency'].to_i * Gitlab::CurrentSettings.zoekt_cpu_to_tasks_ratio).round
        return DEFAULT_CONCURRENCY_LIMIT if calculated_limit == 0

        [calculated_limit, MAX_CONCURRENCY_LIMIT].min
      end

      def metadata_json
        {
          'zoekt.node_name' => metadata['name'],
          'zoekt.node_id' => id,
          'zoekt.used_bytes' => used_bytes,
          'zoekt.indexed_bytes' => indexed_bytes,
          'zoekt.storage_percent_used' => storage_percent_used,
          'zoekt.total_bytes' => total_bytes,
          'zoekt.task_count' => metadata['task_count'],
          'zoekt.concurrency' => metadata['concurrency'],
          'zoekt.concurrency_limit' => concurrency_limit,
          'zoekt.version' => metadata['version']
        }.compact
      end

      def watermark_exceeded_critical?
        storage_percent_used >= WATERMARK_LIMIT_CRITICAL
      end

      def watermark_exceeded_high?
        storage_percent_used >= WATERMARK_LIMIT_HIGH
      end

      def watermark_exceeded_low?
        storage_percent_used >= WATERMARK_LIMIT_LOW
      end

      def storage_percent_used
        return 0 unless total_bytes.to_i > 0

        used_bytes / total_bytes.to_f
      end

      def unclaimed_storage_bytes
        usable_storage_bytes - reserved_storage_bytes
      end

      # Allows callers (e.g., batch workers) to inject a pre-computed value
      # for reserved_storage_bytes, avoiding repeated SUM queries.
      # Use adjust_reserved_storage_bytes_cache to maintain correctness
      # after individual index updates.
      attr_writer :reserved_storage_bytes_cache

      def adjust_reserved_storage_bytes_cache(delta)
        return unless instance_variable_defined?(:@reserved_storage_bytes_cache)

        @reserved_storage_bytes_cache += delta
      end

      def lost?
        threshold = ::Search::Zoekt::Settings.lost_node_threshold
        return false unless threshold

        last_seen_at <= threshold.ago
      end

      def task_pull_frequency
        return TASK_PULL_FREQUENCY_DEFAULT if tasks.pending.limit(concurrency_limit).count < concurrency_limit

        TASK_PULL_FREQUENCY_INCREASED
      end

      def save_debounce
        return true if persisted? && updated_at && (Time.current - updated_at) < DEBOUNCE_DELAY

        save
      end

      def assign_metadata(params)
        metadata['name'] = params.fetch('node.name')
        metadata['task_count'] = params['node.task_count'].to_i if params['node.task_count'].present?
        metadata['concurrency'] = params['node.concurrency'].to_i if params['node.concurrency'].present?
        metadata['version'] = params['node.version'] if params['node.version'].present?
        assign_process_health(params['process_health'].to_h) if params['process_health'].present?
      end

      private

      def assign_process_health(process_health)
        metadata['process_health'] = process_health
        self.webserver_last_seen_at = Time.zone.now if process_health['webserver'].present?
      end

      def free_bytes
        total_bytes - used_bytes
      end

      def reserved_storage_bytes
        return @reserved_storage_bytes_cache if instance_variable_defined?(:@reserved_storage_bytes_cache)

        indices.sum(:reserved_storage_bytes)
      end

      def set_usable_storage_bytes
        self.usable_storage_bytes = free_bytes + indexed_bytes
      end

      def valid_services
        if services.blank?
          errors.add(:services, :blank)
          return
        end

        services.each do |service_num|
          unless SERVICES.has_value?(service_num)
            errors.add(:services, format(_("service %{service_num} doesn't exist"), service_num: service_num))
          end
        end
      end
    end
  end
end
