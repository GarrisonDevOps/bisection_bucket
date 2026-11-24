# frozen_string_literal: true

module Types
  module Ai
    module FlowTrigger
      class LastRunStatusEnum < BaseEnum
        graphql_name 'AiFlowTriggerLastRunStatus'
        description 'Status of the last run of a flow trigger.'

        RunStatusEnum.values.each_value do |run_status|
          value run_status.value.to_s.upcase, value: run_status.value, description: run_status.description
        end

        value 'NEVER', value: :never, description: 'Flow trigger has never run.'
      end
    end
  end
end
