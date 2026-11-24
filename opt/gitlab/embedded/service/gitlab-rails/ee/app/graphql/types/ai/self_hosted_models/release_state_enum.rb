# frozen_string_literal: true

module Types
  module Ai
    module SelfHostedModels
      class ReleaseStateEnum < BaseEnum
        graphql_name 'AiSelfHostedModelReleaseState'
        description 'GitLab release state of the model'

        value 'EXPERIMENTAL', description: 'Experimental status.', value: 'experimental'
        value 'BETA', description: 'Beta status.', value: 'beta'
        value 'GA', description: 'GA status.', value: 'ga'
      end
    end
  end
end
