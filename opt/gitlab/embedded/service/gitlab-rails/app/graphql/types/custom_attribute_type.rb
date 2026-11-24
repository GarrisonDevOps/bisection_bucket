# frozen_string_literal: true

module Types
  # rubocop: disable Gitlab/BoundedContexts -- generic type shared across Projects, Groups, and Users
  class CustomAttributeType < BaseObject
    graphql_name 'CustomAttribute'
    description 'A custom attribute key-value pair. Only available to admins.'

    authorize :read_custom_attribute

    authorize_granular_token permissions: :read_custom_attribute,
      boundaries: [
        { boundary: :project, boundary_type: :project },
        { boundary: :group, boundary_type: :group },
        { boundary: :instance, boundary_type: :instance }
      ],
      assignable_when: [:admin]

    field :key, GraphQL::Types::String,
      null: false,
      description: 'Key of the custom attribute.'

    field :value, GraphQL::Types::String,
      null: false,
      description: 'Value of the custom attribute.'
  end
  # rubocop: enable Gitlab/BoundedContexts
end
