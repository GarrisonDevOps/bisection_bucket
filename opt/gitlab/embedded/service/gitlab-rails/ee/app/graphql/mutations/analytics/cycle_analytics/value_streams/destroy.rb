# frozen_string_literal: true

module Mutations
  module Analytics
    module CycleAnalytics
      module ValueStreams
        class Destroy < BaseMutation
          graphql_name 'ValueStreamDestroy'
          description "Destroy a value stream."

          authorize :delete_value_stream
          authorize_granular_token permissions: :delete_value_stream,
            boundaries: [
              { boundary_argument: :id, boundary: :namespace, boundary_type: :group },
              { boundary_argument: :id, boundary: :project, boundary_type: :project }
            ]

          field :value_stream,
            Types::Analytics::CycleAnalytics::ValueStreamType,
            null: true,
            description: 'Value stream deleted after mutation.'

          argument :id,
            ::Types::GlobalIDType[::Analytics::CycleAnalytics::ValueStream],
            required: true,
            description: 'Global ID of the value stream to destroy.'

          def resolve(id:)
            value_stream = authorized_find!(id: id)

            value_stream.destroy

            {
              value_stream: value_stream.destroyed? ? value_stream : nil,
              errors: value_stream.destroyed? ? [] : [_('Error deleting the value stream')]
            }
          end
        end
      end
    end
  end
end
