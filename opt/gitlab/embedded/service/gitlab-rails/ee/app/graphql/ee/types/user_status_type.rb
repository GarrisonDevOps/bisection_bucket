# frozen_string_literal: true

module EE
  module Types
    module UserStatusType
      extend ActiveSupport::Concern

      prepended do
        field :disabled_for_duo_usage, GraphQL::Types::Boolean, null: false,
          description: 'Indicates if the user is disabled for assignment in Duo features.'
        field :disabled_for_duo_usage_reason, GraphQL::Types::String, null: true,
          description: 'Reason why the user is disabled for assignment in Duo features.'

        def disabled_for_duo_usage
          agent_status_check_result.disabled?
        end

        def disabled_for_duo_usage_reason
          agent_status_check_result.disabled_reason
        end

        private

        def agent_status_check_result
          @agent_status_check_result ||= ::Ai::Agents::CheckAgentStatusService.new(current_user).execute(object.user)
        end
      end
    end
  end
end
