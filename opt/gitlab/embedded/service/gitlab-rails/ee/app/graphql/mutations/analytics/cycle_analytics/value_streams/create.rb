# frozen_string_literal: true

module Mutations
  module Analytics
    module CycleAnalytics
      module ValueStreams
        class Create < BaseMutation
          graphql_name 'ValueStreamCreate'
          description "Creates a value stream."

          include FindsNamespace
          include SharedValueStreamArguments

          authorize :create_value_stream
          authorize_granular_token permissions: :create_value_stream,
            boundaries: [
              { boundary_argument: :namespace_path, boundary_type: :group },
              { boundary_argument: :namespace_path, boundary_type: :project }
            ]

          argument :name, GraphQL::Types::String,
            required: true,
            description: 'Value stream name.'

          argument :stages, [Types::Analytics::CycleAnalytics::ValueStreams::CreateStageInputType],
            required: false,
            description: 'Value stream stages.'

          argument :namespace_path, GraphQL::Types::ID,
            required: true,
            description: 'Full path of the namespace(project or group) the value stream is created in.'

          field :value_stream, Types::Analytics::CycleAnalytics::ValueStreamType,
            null: true,
            description: 'Created value stream.'

          def resolve(namespace_path: nil, **attributes)
            namespace = find_namespace(namespace_path)

            result = ::Analytics::CycleAnalytics::ValueStreams::CreateService.new(
              namespace: namespace,
              params: attributes,
              current_user: current_user).execute

            {
              value_stream: result.success? ? result.payload[:value_stream] : nil,
              errors: result.payload[:errors]&.full_messages || []
            }
          end

          private

          def find_namespace(namespace_path)
            namespace = authorized_find!(namespace_path)

            namespace.is_a?(Project) ? namespace.project_namespace : namespace
          end
        end
      end
    end
  end
end
