# frozen_string_literal: true

module Mutations
  module Analytics
    module CycleAnalytics
      module ValueStreams
        class Update < BaseMutation
          graphql_name 'ValueStreamUpdate'
          description "Updates a value stream."

          include SharedValueStreamArguments

          authorize :update_value_stream
          authorize_granular_token permissions: :update_value_stream,
            boundaries: [
              { boundary_argument: :id, boundary: :namespace, boundary_type: :group },
              { boundary_argument: :id, boundary: :project, boundary_type: :project }
            ]

          argument :id,
            ::Types::GlobalIDType[::Analytics::CycleAnalytics::ValueStream],
            required: true,
            description: 'Global ID of the value stream to update.'

          argument :name, GraphQL::Types::String,
            required: false,
            description: 'Value stream name.'

          argument :stages, [Types::Analytics::CycleAnalytics::ValueStreams::UpdateStageInputType],
            required: false,
            description: 'Value stream stages.'

          field :value_stream, Types::Analytics::CycleAnalytics::ValueStreamType,
            null: true,
            description: 'Updated value stream.'

          def resolve(id:, **params)
            value_stream = authorized_find!(id: id)

            result = ::Analytics::CycleAnalytics::ValueStreams::UpdateService.new(
              namespace: value_stream.namespace,
              params: params,
              current_user: current_user,
              value_stream: value_stream).execute

            {
              value_stream: result.success? ? result.payload[:value_stream] : nil,
              errors: result.payload[:errors]&.full_messages || []
            }
          end
        end
      end
    end
  end
end
