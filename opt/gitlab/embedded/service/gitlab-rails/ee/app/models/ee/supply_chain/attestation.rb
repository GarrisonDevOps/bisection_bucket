# frozen_string_literal: true

module EE
  module SupplyChain
    module Attestation
      extend ActiveSupport::Concern

      prepended do
        include ::Geo::ReplicableModel
        include ::Geo::VerifiableModel

        delegate(*::Geo::VerificationState::VERIFICATION_METHODS, to: :supply_chain_attestation_state)

        with_replicator Geo::SupplyChainAttestationReplicator

        has_one :supply_chain_attestation_state, autosave: false, inverse_of: :supply_chain_attestation,
          class_name: 'Geo::SupplyChainAttestationState'

        scope :project_id_in, ->(ids) { where(project_id: ids) }

        def verification_state_object
          supply_chain_attestation_state
        end
      end

      class_methods do
        extend ::Gitlab::Utils::Override

        override :verification_state_model_key
        def verification_state_model_key
          :supply_chain_attestation_id
        end

        override :verification_state_table_class
        def verification_state_table_class
          ::Geo::SupplyChainAttestationState
        end

        override :pluck_verifiable_ids_in_range
        def pluck_verifiable_ids_in_range(range)
          verifiables(range).pluck_primary_key
        end

        override :selective_sync_scope
        def selective_sync_scope(node, **params)
          replicables = params.fetch(:replicables, all)
          replicables = replicables.primary_key_in(params[:primary_key_in]) if params[:primary_key_in].presence

          return replicables unless node.selective_sync?

          replicables
            .project_id_in(::Project.selective_sync_scope(node).select(:id))
        end
      end

      def supply_chain_attestation_state
        super || build_supply_chain_attestation_state
      end
    end
  end
end
