# frozen_string_literal: true

module Ci
  module PipelineTriggers
    class DestroyService
      include Gitlab::Allowable
      include Ci::PipelineTriggerRateLimitable

      attr_reader :current_user, :trigger

      def initialize(user:, trigger:)
        @current_user = user
        @trigger = trigger
      end

      def execute
        throttled = rate_limited_response(trigger.project, trigger: trigger)

        unless can?(current_user, :manage_trigger, trigger)
          return ServiceResponse.error(
            message: _('The current user is not authorized to manage the pipeline trigger token'),
            reason: :forbidden
          )
        end

        return throttled if throttled

        trigger.destroy

        unless trigger.destroyed?
          return ServiceResponse.error(
            message: _('Attempted to destroy the pipeline trigger token but failed')
          )
        end

        ServiceResponse.success
      end
    end
  end
end
