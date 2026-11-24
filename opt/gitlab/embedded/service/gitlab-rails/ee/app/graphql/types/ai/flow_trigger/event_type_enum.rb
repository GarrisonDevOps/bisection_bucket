# frozen_string_literal: true

module Types
  module Ai
    module FlowTrigger
      class EventTypeEnum < BaseEnum
        graphql_name 'AiFlowTriggerEventType'
        description 'Possible event types for flow triggers.'

        EXPERIMENT_MILESTONES = { scheduled: '19.4', security_policy: '19.6' }.freeze

        ::Ai::FlowTrigger::EVENT_TYPES.each do |event_type, id|
          # Experimental in case they get renamed or redesigned.
          milestone = EXPERIMENT_MILESTONES[event_type]
          value event_type.upcase, description: "Flow trigger #{event_type} event.", value: id,
            experiment: milestone ? { milestone: milestone } : nil
        end
      end
    end
  end
end
