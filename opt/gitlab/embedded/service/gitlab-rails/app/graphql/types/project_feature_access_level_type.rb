# frozen_string_literal: true

# rubocop:disable Graphql/AuthorizeTypes -- It just returns the value of an enum as an integer and a string
module Types
  class ProjectFeatureAccessLevelType < Types::BaseObject
    graphql_name 'ProjectFeatureAccess'
    description 'Represents the access level required by the user to access a project feature'

    authorize_granular_token parent_authorizes: :read_project

    field :integer_value, GraphQL::Types::Int, null: true,
      description: 'Integer representation of access level.',
      method: :to_i

    field :string_value, Types::ProjectFeatureAccessLevelEnum, null: true,
      description: 'String representation of access level.',
      method: :to_i
  end
end
# rubocop:enable Graphql/AuthorizeTypes
