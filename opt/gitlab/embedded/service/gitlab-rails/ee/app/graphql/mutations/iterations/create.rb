# frozen_string_literal: true

module Mutations
  module Iterations
    class Create < BaseMutation
      graphql_name 'iterationCreate'

      include Mutations::ResolvesResourceParent

      authorize :create_iteration
      # Iterations are group-only: `Iteration` belongs to a group and the
      # create service does not support projects, so only a group boundary
      # is declared even though a project_path argument exists.
      authorize_granular_token permissions: :create_iteration, boundary_argument: :group_path,
        boundary_type: :group

      field :iteration,
        Types::IterationType,
        null: true,
        description: 'Created iteration.'

      argument :iterations_cadence_id,
        ::Types::GlobalIDType[::Iterations::Cadence],
        prepare: ->(gid, _) { gid.model_id },
        required: false,
        description: 'Global ID of the iteration cadence to be assigned to the new iteration.'

      argument :title,
        GraphQL::Types::String,
        required: false,
        description: 'Title of the iteration.'

      argument :description,
        GraphQL::Types::String,
        required: false,
        description: 'Description of the iteration.'

      argument :start_date,
        GraphQL::Types::String,
        required: false,
        description: 'Start date of the iteration.'

      argument :due_date,
        GraphQL::Types::String,
        required: false,
        description: 'End date of the iteration.'

      def resolve(args)
        parent = authorized_resource_parent_find!(args)

        validate_arguments!(parent, args)

        response = ::Iterations::CreateService.new(parent, current_user, args).execute

        response_object = response.payload[:iteration] if response.success?
        response_errors = response.error? ? response.payload[:errors] : []

        {
          iteration: response_object,
          errors: response_errors
        }
      end

      private

      def validate_arguments!(parent, args)
        if args.except(:group_path, :project_path).empty?
          raise Gitlab::Graphql::Errors::ArgumentError, 'The list of iteration attributes is empty'
        end
      end
    end
  end
end
