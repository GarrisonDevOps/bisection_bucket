# frozen_string_literal: true

module Mutations
  module Govern
    class PolicyCreate < ::Mutations::BaseMutation
      graphql_name 'GovernPolicyCreate'
      description 'Creates a policy in the policy store for an organization or group.'

      include CommonMutationArguments
      include PolicyStoreMutation

      authorize :create_govern_policy
      # The payload returns the stored policy, so a write-only token must not read it back.
      authorize_granular_token permissions: [:create_govern_policy, :read_govern_policy],
        boundaries: [
          { boundary_argument: :group_path, boundary_type: :group },
          { boundary: :instance, boundary_type: :instance }
        ]

      argument :name, GraphQL::Types::String,
        required: true,
        description: copy_field_description(::Types::Govern::PolicyType, :name)

      argument :trigger_type, GraphQL::Types::String,
        required: true,
        description: copy_field_description(::Types::Govern::PolicyType, :trigger_type)

      # Rules stay JSON for the experiment stage for the same reason as the fields on
      # PolicyType: the content is free-form and owned by the policy store experiment,
      # and a rule value is a hash or a Rego source string.
      argument :rules, [GraphQL::Types::JSON],
        required: true,
        validates: { length: { minimum: 1, maximum: ::Types::BaseArgument::MAX_ARRAY_SIZE } },
        description: 'Rules of the policy, at least one. ' \
          "No more than #{::Types::BaseArgument::MAX_ARRAY_SIZE} rules."

      field :policy, ::Types::Govern::PolicyType,
        null: true,
        description: 'Policy created in the policy store.'

      def resolve(args)
        container = authorized_find!(**args.extract!(*CONTAINER_ARGUMENTS))

        response = ::Security::SecurityOrchestrationPolicies::PolicyStore::CreateService
          .new(container: container, current_user: current_user, params: args)
          .execute

        if response.error?
          # The experiment gate acts as if the API does not exist, while validation
          # failures surface as user-facing errors on the payload. :forbidden is
          # intentionally unmapped: authorized_find! already checks the same ability.
          raise_resource_not_available_error! if response.reason == :experiment_not_active
          # The service already tracked the engine fault; the message names no internals.
          raise GraphQL::ExecutionError, response.message if response.reason == :engine_error

          track_unmapped_reason!(response) unless response.reason.in?(%i[invalid unprocessable])

          return { policy: nil, errors: [response.message] }
        end

        { policy: response.payload[:policy], errors: [] }
      end
    end
  end
end
