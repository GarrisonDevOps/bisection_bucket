# frozen_string_literal: true

module Resolvers
  module Geo
    class UploadRegistriesResolver < BaseResolver
      type ::Types::Geo::UploadRegistryType, null: true

      argument :ids,
        [Types::GlobalIDType[::Geo::UploadRegistry]],
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
        # We can't query other nodes' tracking databases
        return ::Geo::UploadRegistry.none unless GeoNode.current?(object)

        finder_class = if ::Geo::UploadReplicator.replication_enabled?
                         ::Geo::UploadRegistryFinder
                       else
                         ::Geo::UploadPartitionRegistriesFinder
                       end

        finder_class.new(context[:current_user], finder_params(args)).execute
      end

      private

      def finder_params(args)
        {
          ids: registry_ids(args[:ids]),
          replication_state: args[:replication_state],
          verification_state: args[:verification_state],
          keyword: args[:keyword],
          sort: args[:sort]
        }.compact
      end

      def registry_ids(ids)
        ids&.map { |gid| ::GitlabSchema.parse_gid(gid, expected_type: ::Geo::UploadRegistry).model_id }
      end
    end
  end
end
