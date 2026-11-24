# frozen_string_literal: true

module Mutations
  module SecretsManagement
    module Helpers
      module ErrorMessagesHelpers
        extend ActiveSupport::Concern

        def error_messages(operation_result, payload_keys)
          errors = []
          payload_keys.each do |payload_key|
            if operation_result.payload[payload_key]
              errors.concat(errors_on_object(operation_result.payload[payload_key]))
            end
          end
          errors << operation_result.message if operation_result.error? && operation_result.message.present?
          errors
        end
      end
    end
  end
end
