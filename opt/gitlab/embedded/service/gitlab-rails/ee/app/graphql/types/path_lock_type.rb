# frozen_string_literal: true

module Types
  class PathLockType < BaseObject
    graphql_name 'PathLock'
    description 'Represents a file or directory in the project repository that has been locked.'

    authorize :read_path_locks
    authorize_granular_token permissions: :read_code, boundary: :project, boundary_type: :project

    expose_permissions Types::PermissionTypes::Projects::PathLock

    field :id, ::Types::GlobalIDType[PathLock], null: false,
      description: 'ID of the path lock.'

    field :path, GraphQL::Types::String, null: true,
      description: 'Locked path.'

    field :user, ::Types::UserType, null: true,
      description: 'User that has locked the path.'

    field :created_at, Types::TimeType, null: false,
      description: 'Timestamp of when the path was locked.'
  end
end
