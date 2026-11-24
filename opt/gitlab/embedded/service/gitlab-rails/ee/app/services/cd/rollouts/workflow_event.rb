# frozen_string_literal: true

module Cd
  module Rollouts
    class WorkflowEvent
      def initialize(params)
        @params = params
      end

      def type
        params[:type]
      end

      def environment_name
        params.dig(:data, :environment)
      end

      def service_name
        params.dig(:data, :service)
      end

      def step_type
        params.dig(:data, :step_type)
      end

      # An empty position is how the engine reports a refusal belonging to no step, so it
      # reads as nil: '' would send callers looking for a step with an empty path and log
      # every such refusal as unmatched.
      def step_path
        position = params.dig(:data, :position)
        return if position.blank?

        position.join('.')
      end

      def error
        params.dig(:data, :error)
      end

      def reason
        params.dig(:data, :reason)
      end

      def channel_tokens
        params[:channel_tokens] || []
      end

      private

      attr_reader :params
    end
  end
end
