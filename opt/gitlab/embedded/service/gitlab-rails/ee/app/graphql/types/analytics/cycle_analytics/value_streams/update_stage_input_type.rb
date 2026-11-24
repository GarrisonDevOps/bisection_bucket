# frozen_string_literal: true

module Types
  module Analytics
    module CycleAnalytics
      module ValueStreams
        class UpdateStageInputType < CreateStageInputType
          graphql_name 'UpdateValueStreamStageInput'

          description 'Attributes to update value stream stage.'

          argument :id, ::Types::GlobalIDType[::Analytics::CycleAnalytics::Stage],
            required: false,
            description: 'ID of the stage to be updated.'

          # Overrides 'name' argument. Name is not required when updating stages.
          argument :name, GraphQL::Types::String, required: false, description: 'Name of the stage.'

          def prepare
            processed_arguments = super

            processed_arguments[:id] &&= processed_arguments[:id].model_id

            processed_arguments
          end
        end
      end
    end
  end
end
