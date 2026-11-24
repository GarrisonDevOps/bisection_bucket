# frozen_string_literal: true

module Types
  module Cd
    class RolloutGateStatusEnum < BaseEnum
      graphql_name 'CdRolloutGateStatus'
      description 'Decision recorded when resolving a continuous deployment rollout approval gate.'

      value 'APPROVED', value: :approved, description: 'Approve the rollout and allow it to continue.'
      value 'REJECTED', value: :rejected, description: 'Reject the rollout and stop it from continuing.'
    end
  end
end
