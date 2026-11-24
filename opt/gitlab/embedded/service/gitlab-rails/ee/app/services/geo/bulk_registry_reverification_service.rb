# frozen_string_literal: true

module Geo
  # Service that marks registry model state as verification pending in batches
  # to be resynchronized by Geo periodic workers later
  # This service accepts an optional `params` hash containing:
  # - ids, Array: an array of the IDs for the registry records to update (primary keys)
  # - replication_state, String: the state of the registry records to update
  # - verification_state, String: the verification state of the records to be resynchronized
  class BulkRegistryReverificationService < BulkRegistryUpdateService
    extend Gitlab::Utils::Override

    private

    override :attributes_to_update
    def attributes_to_update
      { verification_state: class_to_update.verification_state_value(:verification_pending) }
    end

    override :update_scope
    def update_scope
      pending_relation_from_parameters.verification_not_pending
    end

    override :worker
    def worker
      Geo::BulkRegistryReverificationWorker
    end
  end
end
