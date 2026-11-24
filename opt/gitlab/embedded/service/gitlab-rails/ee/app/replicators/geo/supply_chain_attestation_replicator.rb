# frozen_string_literal: true

module Geo
  class SupplyChainAttestationReplicator < Gitlab::Geo::Replicator
    include ::Geo::BlobReplicatorStrategy

    def self.model
      ::SupplyChain::Attestation
    end

    # @return [String] human-readable title.
    def self.replicable_title
      s_('Geo|Supply Chain Attestation')
    end

    # @return [String] pluralized human-readable title.
    def self.replicable_title_plural
      s_('Geo|Supply Chain Attestations')
    end

    # No GraphQL registry type exists for this replicator, so it is excluded from
    # the RegistrableType union.
    def self.graphql_registerable?
      false
    end

    def carrierwave_uploader
      model_record.file
    end
  end
end
