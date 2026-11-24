# frozen_string_literal: true

module Types
  module Ai
    class ToolSourceEnum < BaseEnum
      graphql_name 'AiToolSource'
      description 'Source of an AI tool.'

      value 'GITLAB', description: 'Tool provided by GitLab.', value: 'gitlab'
      value 'MCP',
        description: "Tool provided via MCP, by the GitLab MCP server or a GitLab client's local MCP server.",
        value: 'mcp'
    end
  end
end
