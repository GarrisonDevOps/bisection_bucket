# frozen_string_literal: true

module Mutations
  module Ai
    module FlowTriggers
      module ServiceResponsePayload
        extend ActiveSupport::Concern

        private

        def service_response_payload(response)
          return { ai_flow_trigger: response.payload, errors: [], error_reason: nil } if response.success?

          { ai_flow_trigger: nil, errors: [response.message], error_reason: error_reason(response.reason) }
        end

        def error_reason(reason)
          reason if reason == ::Ai::FlowTriggers::BaseService::ERROR_REASON_INSUFFICIENT_SERVICE_ACCOUNT_ACCESS
        end
      end
    end
  end
end
