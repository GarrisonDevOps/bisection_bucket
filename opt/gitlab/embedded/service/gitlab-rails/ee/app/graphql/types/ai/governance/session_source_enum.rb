# frozen_string_literal: true

module Types
  module Ai
    module Governance
      class SessionSourceEnum < BaseEnum
        graphql_name 'AiGovernanceSessionSource'
        description 'Source that recorded an AI governance session.'

        DESCRIPTIONS = {
          'gitlab_duo' => 'Session run on the GitLab Duo Agent Platform.',
          'claude_code_compliance_api' => 'Claude Code session ingested from the Claude Compliance API.',
          'claude_code_glab' => 'Claude Code session reported through the GitLab CLI.',
          'mcp' => 'Session inferred from tool calls made through the GitLab MCP server.'
        }.freeze

        ::Ai::Governance::Session.sources.each_key do |source|
          value source.upcase, value: source, description: DESCRIPTIONS.fetch(source)
        end
      end
    end
  end
end
