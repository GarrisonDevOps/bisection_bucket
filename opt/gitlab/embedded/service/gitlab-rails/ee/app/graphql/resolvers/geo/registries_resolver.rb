# frozen_string_literal: true

module Resolvers
  module Geo
    module RegistriesResolver
      extend ActiveSupport::Concern

      included do
        def self.replicator_class
          Gitlab::Geo::Replicator.for_class_name(self.name)
        end

        delegate :registry_class, :registry_finder_class, to: :replicator_class

        type replicator_class.graphql_registry_type, null: true

        argument :ids,
          [Types::GlobalIDType[replicator_class.registry_class]],
          required: false,
          description: 'Filters registries by their ID.'

        argument :replication_state, ::Types::Geo::ReplicationStateEnum,
          required: false,
          description: 'Filters registries by their replication state.'

        argument :verification_state, ::Types::Geo::VerificationStateEnum,
          required: false,
          description: 'Filters registries by their verification state.'

        argument :keyword, GraphQL::Types::String,
          required: false,
          description: 'Filters registries by their attributes using a keyword.',
          deprecated: {
            reason: 'A keyword search feature on Geo registries will not be built in the UI due to
                     poor search UX and performance',
            milestone: '17.9'
          }

        argument :sort, ::Types::Geo::RegistrySortEnum,
          required: false,
          description: 'Sort registries by given criteria.'

        def resolve(**args)
          return registry_class.none unless geo_node_is_current? && replicator_class.replication_enabled?

          registry_finder_class.new(
            context[:current_user],
            registry_finder_params(args)
          ).execute
        end

        private

        def registry_finder_params(args)
          {
            ids: registry_ids(args[:ids]),
            replication_state: args[:replication_state],
            verification_state: args[:verification_state],
            keyword: args[:keyword],
            sort: args[:sort]
          }.compact
        end

        def replicator_class
          self.class.replicator_class
        end

        def registry_ids(ids)
          ids&.map { |gid| ::GitlabSchema.parse_gid(gid, expected_type: registry_class).model_id }
        end

        # We can't query other nodes' tracking databases
        def geo_node_is_current?
          GeoNode.current?(geo_node)
        end

        def geo_node
          object
        end
      end
    end
  end
end
