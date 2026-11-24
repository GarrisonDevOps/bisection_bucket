# frozen_string_literal: true

module Types
  module Cd
    class ServiceInputType < ::Types::BaseInputObject
      graphql_name 'CdServiceInput'
      description 'Attributes for a continuous deployment service.'

      argument :name, GraphQL::Types::String,
        required: true,
        description: copy_field_description(::Types::Cd::ServiceType, :name)

      argument :description, GraphQL::Types::String,
        required: false,
        description: copy_field_description(::Types::Cd::ServiceType, :description)

      argument :artifact_sources, [::Types::Cd::ArtifactSourceInputType],
        required: false,
        validates: { length: { maximum: ::Types::BaseArgument::MAX_ARRAY_SIZE } },
        description: 'Artifact sources to create for the service, ' \
          "up to #{::Types::BaseArgument::MAX_ARRAY_SIZE}."
    end
  end
end
