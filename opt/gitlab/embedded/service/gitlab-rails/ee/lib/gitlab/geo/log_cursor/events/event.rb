# frozen_string_literal: true

module Gitlab
  module Geo
    module LogCursor
      module Events
        class Event
          include BaseEvent

          def process
            if skip_enqueue?
              logger.debug('Skipped enqueue (not in storage scope for current secondary)', event_id: event.id)
              return
            end

            ::Geo::EventWorker.perform_async(event.replicable_name, event.event_name, event.payload)
          end

          private

          def skip_enqueue?
            return false if event.event_name == 'deleted' # We always enqueue deleted events

            # We always enqueue events if the node is set to sync storage
            node = ::Gitlab::Geo.current_node
            return false unless node
            return false if node.sync_object_storage?

            model_class = replicable_model_class
            # We skip the event if the replicable_model_class can't be found to avoid duplicating errors,
            # as the enqueued job would fail with the same error "Cannot find a Geo::Replicator for #{replicable_name}"
            return true unless model_class

            # We always enqueue objects that are not storable
            return false unless model_class.object_storable?

            model_record_id = event.payload['model_record_id']
            return false unless model_record_id
            # At that point, we've established that objects are not synced externally and the model is storable
            # Now, check that the object is in the object_storage_scope for this node (i.e. locally stored). Else, skip.
            return false if locally_stored?(model_class, node, model_record_id)

            true
          end

          # Passes any partition key the payload carries (added by the replicable's #event_params:
          # partition_id for p_ci_job_artifacts, model_type for uploads) so the locality query can
          # prune to a single partition instead of planning an Append across all of them.
          def locally_stored?(model_class, node, model_record_id)
            model_class.object_storage_scope_for(
              node,
              model_record_id,
              model_type: event.payload['model_type'],
              partition_id: event.payload['partition_id']
            ).exists?
          end

          # for_replicable_name raises NotImplementedError for an unrecognized replicable_name.
          # NotImplementedError is a ScriptError, not a StandardError, so it would otherwise pass
          # straight through LogCursor::Daemon's StandardError rescue and crash the daemon.
          def replicable_model_class
            ::Gitlab::Geo::Replicator.for_replicable_name(event.replicable_name).model
          rescue NotImplementedError
            nil
          end
        end
      end
    end
  end
end
