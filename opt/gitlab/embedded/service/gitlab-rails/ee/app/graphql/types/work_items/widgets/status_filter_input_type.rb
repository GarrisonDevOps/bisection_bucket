# frozen_string_literal: true

module Types
  module WorkItems
    module Widgets
      class StatusFilterInputType < BaseInputObject
        graphql_name 'WorkItemWidgetStatusFilterInput'

        argument :id, Types::GlobalIDType[::WorkItems::Statuses::Status],
          required: false,
          description: 'Global ID of the status.',
          prepare: ->(global_id, _) {
            return if global_id.nil?

            status = GitlabSchema.find_by_gid(global_id)

            raise GraphQL::ExecutionError, "Status doesn't exist." if status.nil?

            status
          }

        argument :name, GraphQL::Types::String,
          required: false,
          description: 'Name of the status.'

        validates mutually_exclusive: [:id, :name]
      end
    end
  end
end
