# frozen_string_literal: true

module Types
  class ReleaseSourceType < BaseObject
    graphql_name 'ReleaseSource'
    description 'Represents the source code attached to a release in a particular format'

    authorize :read_code
    authorize_granular_token parent_authorizes: :read_release

    field :format, GraphQL::Types::String, null: true,
      description: 'Format of the source.'
    field :url, GraphQL::Types::String, null: true,
      description: 'Download URL of the source.'
  end
end
