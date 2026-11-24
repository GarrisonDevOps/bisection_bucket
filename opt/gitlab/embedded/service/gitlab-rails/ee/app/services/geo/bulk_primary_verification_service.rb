# frozen_string_literal: true

module Geo
  # Service that marks primary model state as verification_pending in batches
  # to be resynchronized by Geo periodic workers later
  # This service can accept as argument `params` a hash containing:
  # - :identifiers, Array: an array of the IDs for the verification state records to update (not model IDs!)
  # - :checksum_state, String: the verification state of the records to be rechecksummed
  class BulkPrimaryVerificationService < BaseBatchBulkUpdateService
    extend Gitlab::Utils::Override

    private

    override :class_to_update
    def class_to_update
      model_class.verification_state_table_class
    end
    strong_memoize_attr :class_to_update

    override :attributes_to_update
    def attributes_to_update
      { verification_state: 0 }
    end

    override :update_scope
    def update_scope
      scope = class_to_update.verification_state_not_pending
      scope = scope.primary_key_in(params[:identifiers]) unless params[:identifiers].nil?
      scope = scope.with_verification_state(params[:checksum_state]) if params[:checksum_state].present?

      scope
    end

    override :worker
    def worker
      Geo::BulkPrimaryVerificationWorker
    end
  end
end
