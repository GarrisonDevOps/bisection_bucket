# frozen_string_literal: true

module Types
  module RemoteDevelopment
    class WorkspaceVariableTypeEnum < BaseEnum
      graphql_name 'WorkspaceVariableType'
      description 'Enum for the type of the variable injected in a workspace.'

      include ::RemoteDevelopment::Enums::WorkspaceVariable

      WORKSPACE_VARIABLE_TYPES.slice(:environment).each do |name, value|
        value name.to_s.upcase, value: value, description: "#{name.to_s.capitalize} type."
      end

      # @return [Integer]
      def self.environment
        enum[:environment]
      end
    end
  end
end
