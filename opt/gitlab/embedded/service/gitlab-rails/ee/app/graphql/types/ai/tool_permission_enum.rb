# frozen_string_literal: true

module Types
  module Ai
    class ToolPermissionEnum < BaseEnum
      graphql_name 'AiToolPermission'
      description 'Permission mode for an AI tool'

      value 'ALLOW', value: ::Ai::ToolRules::Permissions::ALLOW,
        description: 'Tool is always allowed to run without approval.'
      value 'ASK', value: ::Ai::ToolRules::Permissions::ASK,
        description: 'Tool requires human approval before running.'
      value 'DENY', value: ::Ai::ToolRules::Permissions::DENY,
        description: 'Tool is always blocked from running.'
    end
  end
end
