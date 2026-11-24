# frozen_string_literal: true

module Types
  module Ai
    module Governance
      class AgentClassEnum < BaseEnum
        graphql_name 'AiGovernanceAgentClass'
        description 'Agent class segmentation for AI governance dashboard metrics.'

        value 'ALL', value: :all, description: 'All agent classes, combining internal and external agents.'
        value 'INTERNAL_DAP', value: :internal_dap,
          description: 'Agents running on the internal Duo Agent Platform.'
        value 'EXTERNAL', value: :external,
          description: 'Agents running outside the Duo Agent Platform, ' \
            'such as third-party coding agents.'
      end
    end
  end
end
