# frozen_string_literal: true

module Types
  module Ai
    module FlowsMetadata
      class ClientTypeEnum < BaseEnum
        graphql_name 'AiFlowsMetadataClientType'
        description 'Client surface requesting Duo Agent Platform flow metadata.'

        value 'CLI', description: 'Duo CLI client.', value: :cli
        value 'IDE', description: 'IDE extension client (for example, VS Code or JetBrains).', value: :ide
      end
    end
  end
end
