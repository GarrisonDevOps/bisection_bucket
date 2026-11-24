# frozen_string_literal: true

module Types
  module Cd
    class ArtifactSourceType < ::Types::BaseObject
      graphql_name 'CdArtifactSource'
      description 'Continuous deployment artifact source.'

      connection_type_class Types::CountableConnectionType

      authorize :read_cd_artifact_source
      authorize_granular_token permissions: :read_cd_artifact_source,
        boundaries: [
          { boundary: :instance, boundary_type: :instance }
        ]

      field :id, Types::GlobalIDType[::Cd::ArtifactSource],
        null: false,
        description: 'Global ID of the artifact source.'

      field :name, GraphQL::Types::String,
        null: true,
        description: 'Name of the artifact source.'

      # rubocop:disable GraphQL/ExtractType -- source_ref and source_config are both simple source
      # identifiers, not a logical sub-grouping worth extracting into their own type
      field :source_ref, GraphQL::Types::String,
        null: true,
        description: 'Reference of the artifact source.'

      # rubocop:disable Graphql/JSONType -- source_config is genuinely unstructured: its shape is
      # reflected by the UI from whichever driver consumes it
      field :source_config, GraphQL::Types::JSON,
        null: true,
        description: 'Configuration of the artifact source, defined by the consuming driver.'
      # rubocop:enable Graphql/JSONType
      # rubocop:enable GraphQL/ExtractType

      field :service, ::Types::Cd::ServiceType,
        null: true,
        description: 'Service the artifact source belongs to.'

      field :versions, ::Types::Cd::VersionType.connection_type,
        null: true,
        description: 'Versions of the artifact source.',
        resolver: ::Resolvers::Cd::VersionsResolver,
        experiment: { milestone: '19.2' }

      field :created_at, Types::TimeType,
        null: false,
        description: 'Timestamp of when the artifact source was created.'

      field :updated_at, Types::TimeType,
        null: false,
        description: 'Timestamp of when the artifact source was last updated.'

      def service
        ::Gitlab::Graphql::Loaders::BatchModelLoader.new(::Cd::Service, object.service_id).find
      end
    end
  end
end
