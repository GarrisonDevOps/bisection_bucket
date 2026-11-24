# frozen_string_literal: true

module Types
  module RemoteDevelopment
    class WorkspaceVariableType < ::Types::BaseObject
      graphql_name 'WorkspaceVariable'
      description 'Represents a remote development workspace variable'

      authorize :read_workspace_variable

      field :id, ::Types::GlobalIDType[::RemoteDevelopment::WorkspaceVariable],
        null: false, description: 'Global ID of the workspace variable.'

      field :key, GraphQL::Types::String,
        null: true, description: 'Name of the workspace variable.'

      field :value, GraphQL::Types::String,
        null: true, description: 'Value of the workspace variable.'

      field :variable_type, Types::RemoteDevelopment::WorkspaceVariableTypeEnum,
        null: true, description: 'Type of the workspace variable.'

      field :created_at, Types::TimeType,
        null: false, description: 'Timestamp of when the workspace variable was created.'

      field :updated_at, Types::TimeType,
        null: false, description: 'Timestamp of when the workspace variable was updated.'
    end
  end
end
