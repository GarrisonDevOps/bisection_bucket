# frozen_string_literal: true

module Types
  module Projects
    class ProjectMinimalAccessType < BaseObject
      graphql_name 'ProjectMinimalAccess'

      implements ProjectInterface

      field :avatar_url, GraphQL::Types::String,
        null: true,
        calls_gitaly: true,
        description: 'Avatar URL of the project.'
      field :description, GraphQL::Types::String,
        null: true,
        description: 'Short description of the project.'
      field :full_path, GraphQL::Types::ID,
        null: false,
        description: 'Full path of the project.'
      field :id, GraphQL::Types::ID,
        null: false,
        description: 'ID of the project.'
      field :name, GraphQL::Types::String,
        null: false,
        description: 'Name of the project without the namespace.'
      field :name_with_namespace, GraphQL::Types::String,
        null: false,
        description: 'Name of the project including the namespace.'

      expose_permissions Types::PermissionTypes::Project

      authorize :read_project_metadata
    end
  end
end
