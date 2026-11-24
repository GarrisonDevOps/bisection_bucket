# frozen_string_literal: true

module Types
  module Geo
    class RegistrableType < BaseUnion
      RegistryTypeNotSupportedError = Class.new(StandardError)

      # Derived from Gitlab::Geo::REPLICATOR_CLASSES so the replicator list is the single
      # source of truth. Replicators without a GraphQL registry type are excluded via
      # Replicator.graphql_registerable? (e.g. Geo::SupplyChainAttestationReplicator).
      GEO_REGISTRY_TYPES = ::Gitlab::Geo::REPLICATOR_CLASSES
        .select(&:graphql_registerable?)
        .to_h { |replicator| [replicator.registry_class, replicator.graphql_registry_type] }
        .freeze

      possible_types(*GEO_REGISTRY_TYPES.values)

      def self.resolve_type(object, _)
        registry_type = GEO_REGISTRY_TYPES[object.class]

        raise RegistryTypeNotSupportedError unless registry_type

        registry_type
      end
    end
  end
end
