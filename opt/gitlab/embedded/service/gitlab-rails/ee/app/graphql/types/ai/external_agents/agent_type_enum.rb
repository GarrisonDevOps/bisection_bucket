# frozen_string_literal: true

module Types
  module Ai
    module ExternalAgents
      class AgentTypeEnum < BaseEnum
        graphql_name 'AiExternalAgentType'
        description 'Type of an external agent connected to GitLab through the GitLab CLI.'

        ::Ai::ExternalAgents::AgentIdentity::AGENT_TYPES.each do |agent_type|
          value agent_type.underscore.upcase, value: agent_type, description: "Agent type `#{agent_type}`."
        end
      end
    end
  end
end
