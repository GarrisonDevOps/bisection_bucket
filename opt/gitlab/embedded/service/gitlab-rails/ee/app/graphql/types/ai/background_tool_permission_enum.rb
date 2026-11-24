# frozen_string_literal: true

module Types
  module Ai
    class BackgroundToolPermissionEnum < BaseEnum
      graphql_name 'AiBackgroundToolPermission'
      description 'Permission mode for an AI tool on the background-flow surface. ' \
        '`ask` is not available because no human is present to approve on a background flow.'

      value 'ALLOW', value: ::Ai::ToolRules::Permissions::ALLOW,
        description: 'Tool is always allowed to run without approval.'
      value 'DENY', value: ::Ai::ToolRules::Permissions::DENY,
        description: 'Tool is always blocked from running.'
    end
  end
end
