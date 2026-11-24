# frozen_string_literal: true

module Mutations
  module Terraform
    module State
      class DeletePermanently < BaseMutation
        graphql_name 'TerraformStateDeletePermanently'
        description 'Permanently deletes a Terraform state that is already marked for deletion.'

        authorize :delete_terraform_state
        authorize_granular_token permissions: :delete_terraform_state, boundary_argument: :id, boundary: :project,
          boundary_type: :project

        argument :id,
          Types::GlobalIDType[::Terraform::State],
          required: true,
          description: 'Global ID of the Terraform state.'

        def resolve(id:)
          state = authorized_find!(id: id)
          raise_resource_not_available_error! if Feature.disabled?(:terraform_state_delayed_deletion, state.project)

          response = ::Terraform::States::PermanentDestroyService.new(state, current_user: current_user).execute

          { errors: response.errors }
        end
      end
    end
  end
end
