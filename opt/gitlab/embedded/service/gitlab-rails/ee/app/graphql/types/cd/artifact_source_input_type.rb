# frozen_string_literal: true

module Types
  module Cd
    class ArtifactSourceInputType < ::Types::BaseInputObject
      graphql_name 'CdArtifactSourceInput'
      description 'Attributes for a continuous deployment artifact source.'

      argument :name, GraphQL::Types::String,
        required: true,
        description: copy_field_description(::Types::Cd::ArtifactSourceType, :name)

      argument :source_ref, GraphQL::Types::String,
        required: true,
        description: copy_field_description(::Types::Cd::ArtifactSourceType, :source_ref)

      # rubocop:disable Graphql/JSONType -- source_config is genuinely unstructured: its shape is
      # reflected by the UI from whichever driver consumes it
      argument :source_config, GraphQL::Types::JSON,
        required: false,
        description: copy_field_description(::Types::Cd::ArtifactSourceType, :source_config)
      # rubocop:enable Graphql/JSONType
    end
  end
end
