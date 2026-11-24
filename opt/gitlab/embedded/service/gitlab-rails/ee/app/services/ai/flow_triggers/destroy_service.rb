# frozen_string_literal: true

module Ai
  module FlowTriggers
    class DestroyService < BaseService
      def initialize(trigger:, current_user:)
        @trigger = trigger
        @current_user = current_user
      end

      def execute
        dedicated_account = @trigger.autonomous_service_account

        if @trigger.destroy
          revoke_dedicated_account_access(dedicated_account, @trigger.project)
          audit_flow_trigger('flow_trigger_deleted', @trigger)
          ServiceResponse.success
        else
          ServiceResponse.error(message: 'Failed to delete the flow trigger')
        end
      end
    end
  end
end
