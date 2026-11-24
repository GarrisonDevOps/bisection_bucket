# frozen_string_literal: true

module Search
  module Zoekt
    class PlanningService
      attr_reader :enabled_namespaces, :nodes, :options

      def self.plan(**kwargs)
        new(**kwargs).plan
      end

      def initialize(enabled_namespaces:, nodes:, **options)
        @enabled_namespaces = Array(enabled_namespaces)
        @nodes = format_nodes(nodes)
        @options = options
      end

      def plan
        node_ids_in_use = node_ids_in_use_by_enabled_namespace_id
        all_plans = enabled_namespaces.map do |enabled_namespace|
          Plan.new(enabled_namespace: enabled_namespace, nodes: nodes,
            node_ids_in_use: node_ids_in_use.fetch(enabled_namespace.id, []), **options).generate
        end
        failed_plans, successful_plans = all_plans.partition { |plan| plan[:errors].present? }
        grouped_plans = successful_plans.group_by { |plan| plan[:action] }
        create_plans = grouped_plans.fetch(:create, [])
        destroy_plans = grouped_plans.fetch(:destroy, [])
        unchanged_plans = grouped_plans.fetch(:unchanged, [])

        {
          total_required_storage_bytes: create_plans.sum { |plan| plan[:namespace_required_storage_bytes] },
          create: create_plans,
          destroy: destroy_plans,
          unchanged: unchanged_plans,
          nodes: build_node_change_plan,
          failures: failed_plans
        }
      end

      private

      # One query for the whole batch instead of one per namespace. Bounded by
      # MAX_INDICES_PER_REPLICA * number_of_replicas per namespace, so a 128-namespace
      # batch stays well under MAX_PLUCK in practice.
      def node_ids_in_use_by_enabled_namespace_id
        ids = enabled_namespaces.map(&:id)
        return {} if ids.empty?

        # rubocop: disable CodeReuse/ActiveRecord, Database/AvoidUsingPluckWithoutLimit -- bounded per the comment above
        ::Search::Zoekt::Index.where(zoekt_enabled_namespace_id: ids)
                              .pluck(:zoekt_enabled_namespace_id, :zoekt_node_id)
                              .group_by(&:first)
                              .transform_values { |pairs| pairs.map(&:last) }
        # rubocop: enable CodeReuse/ActiveRecord, Database/AvoidUsingPluckWithoutLimit
      end

      def format_nodes(zoekt_nodes)
        zoekt_nodes.to_a.map do |node|
          {
            id: node[:id],
            name: node.metadata['name'],
            unclaimed_storage_bytes: node[:unclaimed_storage_bytes],
            unclaimed_storage_bytes_before: node[:unclaimed_storage_bytes],
            indices: [],
            namespace_ids: [],
            node: node
          }
        end
      end

      # presentation only
      def build_node_change_plan
        nodes.filter { |hsh| hsh[:indices].present? }.map do |hsh|
          {
            id: hsh[:id],
            name: hsh[:name],
            unclaimed_storage_bytes_before: hsh[:unclaimed_storage_bytes_before],
            unclaimed_storage_bytes_after: hsh[:unclaimed_storage_bytes],
            claimed_storage_bytes: hsh[:indices].sum { |hsh| hsh[:required_storage_bytes] },
            namespace_ids: hsh[:namespace_ids].sort,
            indices: hsh[:indices].sort_by { |hsh| hsh[:namespace_id] }
          }
        end
      end

      class Plan
        include Gitlab::Utils::StrongMemoize

        # Error types that adding Zoekt nodes resolves. RolloutService counts only these.
        CAPACITY_ERROR_TYPES = %i[index_limit_exceeded node_unavailable].freeze

        def initialize(
          enabled_namespace:, nodes:, node_ids_in_use:, max_indices_per_replica: MAX_INDICES_PER_REPLICA)
          @enabled_namespace = enabled_namespace
          @namespace = enabled_namespace.namespace
          @num_replicas = enabled_namespace.number_of_replicas
          @max_indices_per_replica = max_indices_per_replica
          @errors = []
          @replica_plans = []
          @nodes = nodes
          @node_ids_in_use = node_ids_in_use
        end

        def generate
          existing_replicas_count = enabled_namespace.replicas.size
          desired_replicas_count = num_replicas

          result = {
            namespace_id: namespace.id,
            enabled_namespace_id: enabled_namespace.id,
            namespace_required_storage_bytes: 0,
            replicas: [],
            errors: [],
            action: determine_action(existing_replicas_count, desired_replicas_count)
          }

          case result[:action]
          when :create
            replicas_to_create = desired_replicas_count - existing_replicas_count

            if fetch_project_namespaces.exists?
              replicas_to_create.times { simulate_replica_plan }
            else
              replicas_to_create.times { create_empty_replica }
            end

            result[:replicas] = replica_plans
            result[:namespace_required_storage_bytes] = calculate_namespace_storage
          when :destroy
            # For destroy, we don't need to simulate - we'll include replica IDs to delete
            replicas_to_destroy_count = existing_replicas_count - desired_replicas_count
            replicas = enabled_namespace.replicas
            replica_ids = replicas.order(:state).order(id: :desc).limit(replicas_to_destroy_count).pluck_primary_key # rubocop:disable CodeReuse/ActiveRecord -- Just order
            result[:replicas_to_destroy] = replica_ids
          end

          # Update errors after all operations
          result[:errors] = errors.uniq
          result
        end

        private

        attr_reader :enabled_namespace, :namespace, :num_replicas, :max_indices_per_replica, :errors,
          :replica_plans, :nodes, :project_namespace_id

        def determine_action(existing_count, desired_count)
          if existing_count < desired_count
            :create
          elsif existing_count > desired_count
            :destroy
          else
            :unchanged
          end
        end

        def simulate_replica_plan
          replica_indices = []

          fetch_project_namespaces.find_each do |project_namespace|
            project = project_namespace.project
            stats = project&.statistics
            next unless stats

            if replica_indices.size >= max_indices_per_replica
              details = "Replica reached maximum index limit (#{max_indices_per_replica})"
              accumulate_error(replica_plans.size, :index_limit_exceeded, details)
              break
            end

            @project_namespace_id = project_namespace.id
            assign_project_to_index(stats, replica_indices)
          end
          return create_empty_replica if replica_indices.empty?

          add_replica_plan(replica_indices)
        end

        def create_empty_replica
          used = used_node_ids([])
          candidate_nodes = nodes.reject { |n| used.include?(n[:id]) || n[:unclaimed_storage_bytes] < 0 }
          best_node = candidate_nodes.max_by { |node| node[:unclaimed_storage_bytes] }

          if best_node
            replica_indices = [simulate_index(best_node)]
            add_replica_plan(replica_indices)
          else
            accumulate_error(nil, :node_unavailable, "No nodes available to create an empty replica")
          end
        end

        def fetch_project_namespaces
          ::Namespace.by_root_id(namespace.id).project_namespaces.with_project_statistics
        end
        strong_memoize_attr :fetch_project_namespaces

        def find_best_node(stats, excluded_node_ids)
          nodes.find do |n|
            excluded_node_ids.exclude?(n[:id]) && n[:unclaimed_storage_bytes] >= scaled_size(stats)
          end
        end

        # Every node this namespace already has an index on: the ones already persisted, plus all
        # replicas planned so far and the one being packed. zoekt_indices is unique on
        # (zoekt_enabled_namespace_id, zoekt_node_id), so none of them can take another index.
        def used_node_ids(replica_indices)
          planned = replica_plans.flat_map { |rp| rp[:indices].pluck(:node_id) } # rubocop: disable CodeReuse/ActiveRecord, Database/AvoidUsingPluckWithoutLimit -- Just a plain Array
          persisted_node_ids + planned + replica_indices.pluck(:node_id) # rubocop: disable CodeReuse/ActiveRecord, Database/AvoidUsingPluckWithoutLimit -- Just a plain Array
        end

        # Preloaded for the whole batch by PlanningService#plan.
        def persisted_node_ids
          @node_ids_in_use
        end
        strong_memoize_attr :persisted_node_ids

        def assign_project_to_index(stats, replica_indices)
          project_size = scaled_size(stats)
          last_index = replica_indices.last

          if last_index && (last_index[:required_storage_bytes] + project_size) <= last_index[:max_storage_bytes]
            index = last_index
            assigned_node = nodes.find { |n| n[:id] == last_index[:node_id] }
          else
            excluded_node_ids = used_node_ids(replica_indices)
            node = find_best_node(stats, excluded_node_ids)
            if node.nil?
              return accumulate_error(replica_plans.size, :node_unavailable,
                node_unavailable_details(stats, excluded_node_ids))
            end

            index = simulate_index(node)
            replica_indices << index
            node[:indices] ||= []
            node[:indices] << index
            node[:namespace_ids] << namespace.id unless node[:namespace_ids].include?(namespace.id)
            assigned_node = node
          end

          add_project_to_index(index, stats, last_index: last_index)
          assigned_node[:unclaimed_storage_bytes] -= project_size
        end

        # The two causes need different fixes, so they get different wording: either nothing has
        # room for the project, or something does but already holds an index for this namespace.
        def node_unavailable_details(stats, excluded_node_ids)
          if excluded_node_ids.any? && find_best_node(stats, []).present?
            "Every node with capacity for project #{stats.project_id} with size #{scaled_size(stats)} " \
              "already holds an index for this namespace"
          else
            "No node can accommodate project #{stats.project_id} with size #{scaled_size(stats)}"
          end
        end

        def simulate_index(node)
          {
            node_id: node[:id],
            node_name: node[:name],
            namespace_id: namespace.id,
            projects: { project_namespace_id_from: nil, project_namespace_id_to: nil },
            required_storage_bytes: 0,
            max_storage_bytes: node[:unclaimed_storage_bytes]
          }
        end

        def add_project_to_index(index, stats, last_index:)
          unless index == last_index || last_index.nil?
            index[:projects][:project_namespace_id_from] ||= last_index[:projects][:project_namespace_id_to].next
          end

          index[:projects][:project_namespace_id_to] = project_namespace_id
          index[:required_storage_bytes] += scaled_size(stats)
        end

        def add_replica_plan(replica_indices)
          replica_indices.last[:projects][:project_namespace_id_to] = nil if replica_indices.any?

          replica_plans << { indices: replica_indices.map { |index| format_index(index) } }
        end

        def format_index(index)
          index.slice(:node_id, :node_name, :projects, :required_storage_bytes, :max_storage_bytes)
        end

        def calculate_namespace_storage
          replica_plans.sum { |replica| replica[:indices].sum { |index| index[:required_storage_bytes] } }
        end

        def scaled_size(stats)
          stats.repository_size * buffer_factor
        end

        def buffer_factor
          ::Search::Zoekt::Index.global_buffer_factor
        end
        strong_memoize_attr :buffer_factor

        def accumulate_error(replica_idx, type, details)
          @errors << { namespace_id: namespace.id, replica_idx: replica_idx, type: type, details: details }
        end
      end
    end
  end
end
