# frozen_string_literal: true

module Mutations
  module Iterations
    class Delete < BaseMutation
      graphql_name 'IterationDelete'

      AUTOMATIC_CADENCE_ERROR = 'Deleting iterations from automatic iteration cadences is not allowed.'

      authorize :admin_iteration
      authorize_granular_token permissions: :delete_iteration, boundary_argument: :id, boundary: :group,
        boundary_type: :group

      argument :id, ::Types::GlobalIDType[::Iteration],
        required: true,
        description: copy_field_description(Types::IterationType, :id)

      field :group, ::Types::GroupType, null: false, description: 'Group the iteration belongs to.'

      def resolve(id:)
        iteration = authorized_find!(id: id)

        reject_if_automatic_cadence!(iteration)

        response = ::Iterations::DeleteService.new(iteration, current_user).execute

        {
          group: response.payload[:group],
          errors: response.errors
        }
      end

      private

      def reject_if_automatic_cadence!(iteration)
        return unless iteration.iterations_cadence.automatic?

        raise Gitlab::Graphql::Errors::MutationError, AUTOMATIC_CADENCE_ERROR
      end
    end
  end
end
