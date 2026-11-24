# frozen_string_literal: true

module Types
  module Analytics
    module CycleAnalytics
      module ValueStreams
        class SettingInputType < Types::BaseInputObject
          graphql_name 'ValueStreamSettingInput'

          description 'Attributes for value stream setting.'

          argument :project_ids_filter,
            [::Types::GlobalIDType[::Project]],
            required: false,
            description: "Projects' global IDs used to filter value stream data."

          def prepare
            processed_arguments = to_h

            processed_arguments[:project_ids_filter] &&= processed_arguments[:project_ids_filter].map(&:model_id)

            processed_arguments
          end
        end
      end
    end
  end
end
