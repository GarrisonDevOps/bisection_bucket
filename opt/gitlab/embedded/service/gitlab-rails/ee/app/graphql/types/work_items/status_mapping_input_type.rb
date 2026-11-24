# frozen_string_literal: true

module Types
  module WorkItems
    class StatusMappingInputType < BaseInputObject
      graphql_name 'StatusMappingInput'

      description 'Input for mapping a removed status to a replacement status'

      argument :old_status_id, ::Types::GlobalIDType[::WorkItems::Statuses::Status],
        required: true,
        description: 'Global ID of the status being removed/replaced.'

      argument :new_status_id, ::Types::GlobalIDType[::WorkItems::Statuses::Status],
        required: true,
        description: 'Global ID of the replacement status.'
    end
  end
end
