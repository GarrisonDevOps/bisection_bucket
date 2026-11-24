# frozen_string_literal: true

module Types
  module Ai
    module FlowTrigger
      class KindEnum < BaseEnum
        graphql_name 'AiFlowTriggerKind'
        description 'Kinds of flow triggers.'

        value 'SCHEDULED', 'Flow trigger that runs on a schedule.', value: :scheduled,
          experiment: { milestone: '19.6' }
        value 'EVENT', 'Flow trigger that runs when an event occurs.', value: :event
      end
    end
  end
end
