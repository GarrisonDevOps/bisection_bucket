# frozen_string_literal: true

module Types
  module RemoteDevelopment
    class WorkspaceVariableInput < BaseInputObject
      graphql_name 'WorkspaceVariableInput'
      description 'Attributes for defining a variable to be injected in a workspace.'

      # do not allow empty values. also validate that the key contains only alphanumeric characters, -, _ or .
      # https://kubernetes.io/docs/concepts/configuration/secret/#restriction-names-data
      argument :key, GraphQL::Types::String,
        description: 'Name of the workspace variable.'
      argument :type, Types::RemoteDevelopment::WorkspaceVariableInputTypeEnum,
        required: false,
        default_value: Types::RemoteDevelopment::WorkspaceVariableInputTypeEnum.environment,
        replace_null_with_default: true,
        description: 'Type of the variable to be injected in a workspace.',
        deprecated: { reason: 'Use `variableType` instead', milestone: '17.9' }
      argument :value, GraphQL::Types::String, description: 'Value of the variable.'
      argument :variable_type, Types::RemoteDevelopment::WorkspaceVariableTypeEnum,
        required: false,
        default_value: Types::RemoteDevelopment::WorkspaceVariableTypeEnum.environment,
        replace_null_with_default: true,
        description: 'Type of the variable to be injected in a workspace.'
    end
  end
end
