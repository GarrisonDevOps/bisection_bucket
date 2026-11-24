# frozen_string_literal: true

module Geo
  # Service that marks registry model state as pending in batches
  # to be resynchronized by Geo periodic workers later
  # This service accepts an optional `params` hash containing:
  # - ids, Array: an array of the IDs for the registry records to update (primary keys)
  # - replication_state, String: the state of the registry records to update
  # - verification_state, String: the verification state of the records to be resynchronized
  class BulkRegistryResyncService < BulkRegistryUpdateService
    extend Gitlab::Utils::Override

    private

    override :attributes_to_update
    def attributes_to_update
      { state: class_to_update.state_value(:pending) }
    end

    override :update_scope
    def update_scope
      pending_relation_from_parameters.not_pending
    end

    override :worker
    def worker
      Geo::BulkRegistryResyncWorker
    end
  end
end
