# frozen_string_literal: true

module Geo
  class SupplyChainAttestationState < ApplicationRecord
    include ::Geo::VerificationStateDefinition

    belongs_to :supply_chain_attestation, inverse_of: :supply_chain_attestation_state,
      class_name: 'SupplyChain::Attestation'

    validates :verification_state, :supply_chain_attestation, presence: true
  end
end
