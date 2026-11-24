# frozen_string_literal: true

module Types
  module WorkItems
    module Widgets
      class StatusInputType < BaseInputObject
        graphql_name 'WorkItemWidgetStatusInput'

        argument :status, Types::GlobalIDType[::WorkItems::Statuses::Status],
          required: false,
          description: 'Global ID of the status. Mutually exclusive with `name`.',
          prepare: ->(global_id, _) do
            return if global_id.nil?

            status = GitlabSchema.find_by_gid(global_id)
            status = status.sync if status.respond_to?(:sync)

            raise GraphQL::ExecutionError, "Status doesn't exist." if status.nil?

            status
          end

        argument :name, GraphQL::Types::String,
          required: false,
          description: "Name of the status. Resolved case-insensitively against the work item's " \
            'status lifecycle. Mutually exclusive with `status`.'

        validates mutually_exclusive: [:status, :name]
      end
    end
  end
end
