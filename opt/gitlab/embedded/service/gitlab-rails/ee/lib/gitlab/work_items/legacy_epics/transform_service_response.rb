# frozen_string_literal: true

module Gitlab
  module WorkItems
    module LegacyEpics
      class TransformServiceResponse
        ALREADY_ASSIGNED_ERROR_MSG = "already assigned"
        NOT_FOUND_ERROR_MSG = "No matching work item found"

        def initialize(result:)
          @result = result
        end

        def transform(created_references_lambda:, error_message_lambda:)
          if result[:status] == :success
            success(created_references_lambda.call)
          else
            error(error_message_lambda.call)
          end
        end

        private

        attr_reader :result

        def success(created_references)
          result.delete(:message)
          result.delete(:work_item)
          result[:status] = :success
          result[:created_references] = created_references
          result
        end

        def error(error_message_creator)
          result[:http_status] = 422 if result[:http_status] == :unprocessable_entity

          if result[:message].include?(ALREADY_ASSIGNED_ERROR_MSG)
            result[:http_status] = 409
            result[:message] = error_message_creator.already_assigned
          elsif result[:message].include?(NOT_FOUND_ERROR_MSG)
            result[:http_status] = 404
            result[:message] = error_message_creator.not_found
          end

          result
        end
      end
    end
  end
end
