# frozen_string_literal: true

module Mutations
  module Environments
    class Delete < ::Mutations::BaseMutation
      graphql_name 'EnvironmentDelete'
      description 'Delete an environment. When the `environment_delete_in_batches` feature flag is enabled, ' \
        'a large environment is deleted over several requests: each request returns an error in `errors` until ' \
        'the environment is gone, and the rows deleted count toward a per-user rate limit ' \
        '(`environment_delete_rows_limit_per_user` application setting). Until the ' \
        '`rate_limit_environment_delete_rows` feature flag is enabled, requests over this limit are logged but ' \
        'not blocked.'

      authorize :destroy_environment
      authorize_granular_token permissions: :delete_environment, boundary_argument: :id, boundary: :project,
        boundary_type: :project

      argument :id,
        ::Types::GlobalIDType[::Environment],
        required: true,
        description: 'Global ID of the environment to Delete.'

      def resolve(id:, **kwargs)
        environment = authorized_find!(id: id)

        response = ::Environments::DestroyService.new(environment.project, current_user, kwargs).execute(environment)

        if response.success?
          { errors: [] }
        else
          { errors: response.errors }
        end
      end
    end
  end
end
