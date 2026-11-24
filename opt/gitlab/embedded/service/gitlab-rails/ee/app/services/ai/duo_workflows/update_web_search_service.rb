# frozen_string_literal: true

module Ai
  module DuoWorkflows
    class UpdateWebSearchService # rubocop:disable Search/NamespacedClass -- not search infrastructure, web_search is a Duo Chat feature toggle
      def initialize(workflow:, web_search_enabled:, current_user:)
        @workflow = workflow
        @web_search_enabled = web_search_enabled
        @current_user = current_user
      end

      def execute
        unless Ability.allowed?(@current_user, :update_duo_workflow, @workflow)
          return error_response("Cannot update workflow", :unauthorized)
        end

        @workflow.web_search_enabled = @web_search_enabled

        if @workflow.save
          ServiceResponse.success(
            payload: { workflow: @workflow },
            message: "Web search setting updated successfully"
          )
        else
          error_response("Failed to update web search setting: #{@workflow.errors.full_messages.join(', ')}")
        end
      end

      private

      def error_response(message, reason = :bad_request)
        ServiceResponse.error(message: message, reason: reason)
      end
    end
  end
end
