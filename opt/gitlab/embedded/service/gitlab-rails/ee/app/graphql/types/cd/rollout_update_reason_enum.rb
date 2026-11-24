# frozen_string_literal: true

module Types
  module Cd
    class RolloutUpdateReasonEnum < BaseEnum
      graphql_name 'CdRolloutUpdateReason'
      description 'Reason a rollout update was pushed to the client.'

      value 'DEPLOYMENT_FAILED', value: :deployment_failed,
        description: 'Rollout failed and Duo opened an investigation session.'
      value 'DEPLOYMENT_CREATED', value: :deployment_created,
        description: 'New rollout was created and Duo opened a session for it.'
    end
  end
end
