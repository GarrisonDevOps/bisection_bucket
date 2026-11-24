# frozen_string_literal: true

module Geo
  # This class groups the common methods used by bulk registry update subclasses
  # BulkReverificationService and BulkResyncService
  class BulkRegistryUpdateService < BaseBatchBulkUpdateService
    extend Gitlab::Utils::Override

    private

    override :class_to_update
    def class_to_update
      model_class
    end
    strong_memoize_attr :class_to_update

    def pending_relation_from_parameters
      relation = class_to_update
      relation = relation.id_in(params[:ids]) if params[:ids]
      relation = relation.with_state(params[:replication_state]) if params[:replication_state]

      if params[:verification_state] && class_to_update.replicator_class.verification_enabled?
        relation = relation.with_verification_state(params[:verification_state])
      end

      relation
    end
  end
end
