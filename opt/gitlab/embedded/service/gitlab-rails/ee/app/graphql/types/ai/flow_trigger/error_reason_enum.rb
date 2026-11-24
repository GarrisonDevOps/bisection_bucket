# frozen_string_literal: true

module Types
  module Ai
    module FlowTrigger
      class ErrorReasonEnum < BaseEnum
        graphql_name 'AiFlowTriggerErrorReason'
        description 'Reasons a flow trigger mutation failed.'

        value 'INSUFFICIENT_SERVICE_ACCOUNT_ACCESS',
          'Access of the user does not cover the service account that the scheduled automation runs as.',
          value: ::Ai::FlowTriggers::BaseService::ERROR_REASON_INSUFFICIENT_SERVICE_ACCOUNT_ACCESS
      end
    end
  end
end
