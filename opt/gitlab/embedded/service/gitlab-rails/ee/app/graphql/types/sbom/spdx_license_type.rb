# frozen_string_literal: true

module Types
  module Sbom
    # rubocop:disable Graphql/AuthorizeTypes -- Static catalogue data available to any authenticated user.
    class SpdxLicenseType < BaseObject
      graphql_name 'SpdxLicense'
      description 'SPDX license entry from the SPDX licence catalogue.'

      authorize_granular_token permissions: :read_metadata, boundary: :instance, boundary_type: :instance

      field :name, GraphQL::Types::String,
        null: false, description: 'Full name of the license.'

      field :spdx_identifier, GraphQL::Types::String,
        null: false, description: 'SPDX identifier of the license.'

      field :url, GraphQL::Types::String,
        null: true, description: 'URL to the SPDX license page.'

      def url
        return if object.id == 'unknown'

        object.url
      end
    end
    # rubocop:enable Graphql/AuthorizeTypes
  end
end
