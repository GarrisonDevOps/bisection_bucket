# frozen_string_literal: true

module Search
  module Zoekt
    class ReplicaSelector
      # Result object that holds both the selected replica and its available nodes
      Result = Data.define(:replica, :nodes) do
        def present?
          replica.present? && nodes.present?
        end

        def empty?
          !present?
        end
      end

      def initialize(enabled_namespace)
        @enabled_namespace = enabled_namespace
      end

      # Selects the best replica for search based on load balancing
      # Returns a Result object containing the replica and its online nodes
      def select
        replica_nodes_map = Node.for_search.searchable.replica_map_for_enabled_namespace(enabled_namespace)

        return Result.new(replica: nil, nodes: []) if replica_nodes_map.empty?

        if replica_nodes_map.size == 1
          replica_id, nodes = replica_nodes_map.first
          replica = enabled_namespace.replicas.find(replica_id)
          return Result.new(replica: replica, nodes: nodes)
        end

        # For each replica, find a representative node using load balancer
        # Then pick the replica whose representative node has the lowest load
        selected_replica_id = replica_nodes_map.keys.min_by do |replica_id|
          nodes = replica_nodes_map[replica_id]
          next Float::INFINITY if nodes.empty?

          # Use load balancer to pick the node with lowest load
          load_balancer = LoadBalancer.new(nodes)
          chosen_node = load_balancer.pick
          next Float::INFINITY unless chosen_node

          # Get the current load of this node
          load_balancer.distribution.find { |d| d[:node_id] == chosen_node.id }&.dig(:current_load) || 0
        end

        replica = enabled_namespace.replicas.find(selected_replica_id)
        nodes = replica_nodes_map[selected_replica_id] || []
        Result.new(replica: replica, nodes: nodes)
      end

      private

      attr_reader :enabled_namespace
    end
  end
end
