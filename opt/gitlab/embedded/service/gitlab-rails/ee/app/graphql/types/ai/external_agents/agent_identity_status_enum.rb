# frozen_string_literal: true

module Types
  module Ai
    module ExternalAgents
      class AgentIdentityStatusEnum < BaseEnum
        graphql_name 'AiAgentIdentityStatus'
        description 'Status of an external agent identity.'

        value 'ACTIVE', value: :active,
          description: 'Not revoked, and synced in the last 30 days, or registered in the last 30 days ' \
            'and not synced yet.'
        value 'INACTIVE', value: :inactive, description: 'Not revoked, and not active.'
        value 'REVOKED', value: :revoked, description: 'Revoked, so the agent can no longer sync sessions.'
      end
    end
  end
end
