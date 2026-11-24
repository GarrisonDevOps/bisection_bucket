# frozen_string_literal: true

module Mutations
  module Govern
    module CommonMutationArguments
      extend ActiveSupport::Concern

      included do
        argument :description, GraphQL::Types::String,
          required: false,
          description: copy_field_description(::Types::Govern::PolicyType, :description)

        # Actions and the scope stay JSON for the experiment stage for the same
        # reason as the fields on PolicyType: the content is free-form and owned
        # by the policy store experiment.
        argument :actions, [GraphQL::Types::JSON],
          required: false,
          validates: { length: { maximum: ::Types::BaseArgument::MAX_ARRAY_SIZE } },
          description: 'Actions the policy takes. ' \
            "No more than #{::Types::BaseArgument::MAX_ARRAY_SIZE} actions."

        argument :policy_scope, GraphQL::Types::JSON, # rubocop:disable Graphql/JSONType -- free-form experiment content (see comment)
          required: false,
          description: 'Authored scope of the policy. Mutually exclusive with scopeRego.'

        argument :scope_rego, GraphQL::Types::String,
          required: false,
          description: copy_field_description(::Types::Govern::PolicyType, :scope_rego)

        argument :mode, GraphQL::Types::String,
          required: false,
          description: copy_field_description(::Types::Govern::PolicyType, :mode)

        argument :lifecycle_state, GraphQL::Types::String,
          required: false,
          description: copy_field_description(::Types::Govern::PolicyType, :lifecycle_state)
      end
    end
  end
end
