# frozen_string_literal: true

module Geo
  class SupplyChainAttestationRegistry < Geo::BaseRegistry
    include ::Geo::ReplicableRegistry
    include ::Geo::VerifiableRegistry

    belongs_to :supply_chain_attestation, class_name: 'SupplyChain::Attestation'

    def self.model_class
      ::SupplyChain::Attestation
    end

    def self.model_foreign_key
      :supply_chain_attestation_id
    end
  end
end
