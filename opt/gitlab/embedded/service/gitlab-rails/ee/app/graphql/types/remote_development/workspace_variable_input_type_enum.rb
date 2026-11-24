# frozen_string_literal: true

module Types
  module RemoteDevelopment
    class WorkspaceVariableInputTypeEnum < BaseEnum
      graphql_name 'WorkspaceVariableInputType'
      description 'Enum for the type of the variable to be injected in a workspace.'

      include ::RemoteDevelopment::Enums::WorkspaceVariable

      from_rails_enum(WORKSPACE_VARIABLE_TYPES_FOR_GRAPHQL, description: "#{%(name).capitalize} type.")

      # @return [Integer]
      def self.environment
        enum[:environment]
      end
    end
  end
end
