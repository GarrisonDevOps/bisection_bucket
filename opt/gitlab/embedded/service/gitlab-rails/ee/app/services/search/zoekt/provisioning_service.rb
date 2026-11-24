# frozen_string_literal: true

module Search
  module Zoekt
    class ProvisioningService
      def self.execute(plan)
        new(plan).execute
      end

      attr_reader :plan, :errors

      def initialize(plan)
        @plan = plan
        @errors = []
        @success = []
      end

      def execute
        plan[:failures].each { |failed_namespace_plan| update_enabled_namespace(failed_namespace_plan) }

        # Process namespaces to create
        plan[:create].each do |namespace_plan|
          process_namespace_create(namespace_plan)
        end

        # Process namespaces to destroy replicas
        plan[:destroy].each do |namespace_plan|
          ApplicationRecord.transaction do
            process_namespace_destroy(namespace_plan)
          end
        rescue StandardError => e
          aggregate_error(e.message, failed_namespace_id: namespace_plan[:namespace_id])
        end

        { errors: @errors, success: @success }
      end

      private

      def process_namespace_create(namespace_plan)
        namespace_id = namespace_plan.fetch(:namespace_id)
        # Remove any pre-existing replicas for this namespace since we are provisioning new ones.
        enabled_namespace = Search::Zoekt::EnabledNamespace.for_root_namespace_id(namespace_id).first
        if enabled_namespace.nil?
          aggregate_error(:missing_enabled_namespace, failed_namespace_id: namespace_id)
          return
        end

        # For create action, we add new replicas without deleting existing ones
        enabled_namespace_id = namespace_plan.fetch(:enabled_namespace_id)
        successful_replicas = 0
        total_replicas = namespace_plan[:replicas].size

        namespace_plan[:replicas].each do |replica_plan|
          ApplicationRecord.transaction do
            process_replica(
              namespace_id: namespace_id,
              enabled_namespace_id: enabled_namespace_id,
              replica_plan: replica_plan
            )
            successful_replicas += 1
          end
        rescue NodeStorageError => e
          json = Gitlab::Json.safe_parse(e.message, symbolize_names: true)
          aggregate_error(
            json[:message],
            failed_namespace_id: json[:namespace_id],
            node_id: json[:node_id],
            node_name: json[:node_name]
          )
        rescue StandardError => e
          aggregate_error(e.message)
        end

        # Update enabled_namespace based on whether any replicas succeeded
        if successful_replicas > 0
          # At least one replica succeeded, reset the failure timestamp
          update_enabled_namespace(namespace_plan, reset: true)
        elsif total_replicas > 0
          # All replicas failed, mark as failed
          update_enabled_namespace(namespace_plan, reset: false)
        end
      end

      def process_namespace_destroy(namespace_plan)
        namespace_id = namespace_plan.fetch(:namespace_id)
        enabled_namespace = Search::Zoekt::EnabledNamespace.find_by_root_namespace_id(namespace_id)
        if enabled_namespace.nil?
          aggregate_error(:missing_enabled_namespace, failed_namespace_id: namespace_id)
          return
        end

        # Delete specified replicas
        replica_ids = namespace_plan[:replicas_to_destroy] || []
        deleted_count = enabled_namespace.replicas.id_in(replica_ids).delete_all

        return unless deleted_count > 0

        aggregate_success_destroy(namespace_id, deleted_count)
      end

      def process_replica(namespace_id:, enabled_namespace_id:, replica_plan:)
        replica = Replica.create!(namespace_id: namespace_id, zoekt_enabled_namespace_id: enabled_namespace_id)
        process_indices!(replica, replica_plan[:indices])
      end

      def process_indices!(replica, indices_plan)
        zoekt_indices = indices_plan.map do |index_plan|
          node = Node.for_search.find_by_id(index_plan[:node_id])
          unless node
            raise NodeStorageError, {
              message: 'node_not_found',
              namespace_id: replica.namespace_id,
              node_id: index_plan[:node_id],
              node_name: index_plan[:node_name]
            }.to_json
          end

          required_storage_bytes = index_plan[:required_storage_bytes]
          if required_storage_bytes > node.unclaimed_storage_bytes
            raise NodeStorageError, {
              message: 'node_capacity_exceeded',
              namespace_id: replica.namespace_id,
              node_id: node.id,
              node_name: node.metadata['name']
            }.to_json
          end

          {
            zoekt_enabled_namespace_id: replica.zoekt_enabled_namespace_id,
            zoekt_replica_id: replica.id,
            zoekt_node_id: node.id,
            namespace_id: replica.namespace_id,
            reserved_storage_bytes: required_storage_bytes,
            metadata: index_plan[:projects].compact
          } # Workaround: we remove nil project_namespace_id_to since it is not a valid property in json validator.
        end
        Index.insert_all!(zoekt_indices)
        aggregate_success(replica)
      end

      def aggregate_error(message, failed_namespace_id: nil, node_id: nil, node_name: nil)
        @errors << {
          message: message,
          failed_namespace_id: failed_namespace_id,
          node_id: node_id,
          node_name: node_name
        }
      end

      def aggregate_success(replica)
        @success << { namespace_id: replica.namespace_id, replica_id: replica.id }
      end

      def aggregate_success_destroy(namespace_id, deleted_count)
        @success << { namespace_id: namespace_id, replicas_destroyed: deleted_count }
      end

      def update_enabled_namespace(namespace_plan, reset: false)
        enabled_ns = EnabledNamespace.for_root_namespace_id(namespace_plan[:namespace_id]).with_limit(1).first
        return unless enabled_ns

        if reset
          enabled_ns.last_rollout_failed_at = nil
        else
          enabled_ns.last_rollout_failed_at = Time.current.iso8601
          # The plan's bytes are scaled by a fractional buffer factor, and the metadata schema only allows integers.
          enabled_ns.metadata['rollout_required_storage_bytes'] = namespace_plan[:namespace_required_storage_bytes].ceil
        end

        enabled_ns.save!
      end
    end

    NodeStorageError = Class.new(StandardError)
  end
end
