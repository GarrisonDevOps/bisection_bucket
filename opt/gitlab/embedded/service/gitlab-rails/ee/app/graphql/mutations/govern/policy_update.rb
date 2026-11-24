# frozen_string_literal: true

module Mutations
  module Govern
    class PolicyUpdate < ::Mutations::BaseMutation
      graphql_name 'GovernPolicyUpdate'
      description 'Updates a policy in the policy store for an organization or group. ' \
        'Only the supplied fields are changed; omitted fields keep their current values, ' \
        'while an explicit null clears a nullable field.'

      include CommonMutationArguments
      include PolicyStoreMutation

      # Everything the client may change. Slicing against this keeps a future argument
      # added for the mutation itself from reaching the store as a policy attribute.
      UPDATABLE_ARGUMENTS = %i[
        name description trigger_type rules actions policy_scope scope_rego mode lifecycle_state
      ].freeze

      authorize :update_govern_policy
      # The payload returns the stored policy, so a write-only token must not read it back.
      authorize_granular_token permissions: [:update_govern_policy, :read_govern_policy],
        boundaries: [
          { boundary_argument: :group_path, boundary_type: :group },
          { boundary: :instance, boundary_type: :instance }
        ]

      # Plain Int, not GlobalID: policies are frozen gem value objects that cannot
      # build GlobalIDs, and the REST endpoint round-trips the same integer id.
      argument :policy_id, GraphQL::Types::Int,
        required: true,
        description: copy_field_description(::Types::Govern::PolicyType, :id)

      argument :name, GraphQL::Types::String,
        required: false,
        description: copy_field_description(::Types::Govern::PolicyType, :name)

      argument :trigger_type, GraphQL::Types::String,
        required: false,
        description: copy_field_description(::Types::Govern::PolicyType, :trigger_type)

      argument :rules, [GraphQL::Types::JSON],
        required: false,
        validates: { length: { minimum: 1, maximum: ::Types::BaseArgument::MAX_ARRAY_SIZE } },
        description: 'Rules of the policy, at least one when supplied. ' \
          "No more than #{::Types::BaseArgument::MAX_ARRAY_SIZE} rules."

      field :policy, ::Types::Govern::PolicyType,
        null: true,
        description: 'Policy updated in the policy store.'

      def resolve(policy_id:, **args)
        container = authorized_find!(**args.extract!(*CONTAINER_ARGUMENTS))

        response = ::Security::SecurityOrchestrationPolicies::PolicyStore::UpdateService
          .new(
            container: container,
            current_user: current_user,
            policy_id: policy_id,
            # Only the keys the client supplied survive the slice -> partial update.
            params: args.slice(*UPDATABLE_ARGUMENTS)
          ).execute

        if response.error?
          # The experiment gates and a missing policy act as if the API does not exist,
          # while validation failures surface as user-facing errors on the payload.
          # :forbidden is intentionally unmapped: authorized_find! already checks the
          # same ability, so reaching it here means the two checks have diverged.
          raise_resource_not_available_error! if [:experiment_not_active, :not_found].include?(response.reason)
          # The service already tracked the engine fault; the message names no internals.
          raise GraphQL::ExecutionError, response.message if response.reason == :engine_error

          track_unmapped_reason!(response) unless response.reason == :invalid

          return { policy: nil, errors: [response.message] }
        end

        { policy: response.payload[:policy], errors: [] }
      end
    end
  end
end
