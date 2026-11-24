# frozen_string_literal: true

module Types
  module Analytics
    module CycleAnalytics
      module ValueStreams
        class CreateStageInputType < Types::BaseInputObject
          graphql_name 'CreateValueStreamStageInput'

          description 'Attributes to create value stream stage.'

          argument :name, GraphQL::Types::String, required: true, description: 'Name of the stage.'

          argument :custom, GraphQL::Types::Boolean,
            required: false,
            default_value: true,
            description: 'Whether the stage is customized. If false, it assigns a built-in default stage by name.'

          argument :end_event_identifier, StageEventEnum, required: false, description: 'End event identifier.'
          argument :end_event_label_id, ::Types::GlobalIDType[::Label], required: false,
            description: 'Label ID associated with the end event identifier.'
          argument :hidden, GraphQL::Types::Boolean, required: false, description: 'Whether the stage is hidden.'
          argument :start_event_identifier, StageEventEnum, required: false, description: 'Start event identifier.'
          argument :start_event_label_id, ::Types::GlobalIDType[::Label], required: false,
            description: 'Label ID associated with the start event identifier.'

          def prepare
            processed_arguments = to_h

            processed_arguments[:start_event_label_id] &&= processed_arguments[:start_event_label_id].model_id
            processed_arguments[:end_event_label_id] &&= processed_arguments[:end_event_label_id].model_id

            processed_arguments
          end
        end
      end
    end
  end
end
