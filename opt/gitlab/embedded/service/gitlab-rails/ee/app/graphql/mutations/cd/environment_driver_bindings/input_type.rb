# frozen_string_literal: true

module Mutations
  module Cd
    module EnvironmentDriverBindings
      class InputType < ::Types::BaseInputObject
        graphql_name 'CdEnvironmentDriverBindingInput'
        description 'Attributes for a continuous deployment environment driver binding.'

        argument :driver_ref, GraphQL::Types::String,
          required: true,
          description: copy_field_description(::Types::Cd::EnvironmentDriverBindingType, :driver_ref)

        # rubocop:disable Graphql/JSONType -- driver_config is genuinely unstructured: its shape is defined by
        # whichever driver produced it (see Cd::DeployDrivers::Registry and the model's schema validation)
        argument :driver_config, GraphQL::Types::JSON,
          required: true,
          description: copy_field_description(::Types::Cd::EnvironmentDriverBindingType, :driver_config)
        # rubocop:enable Graphql/JSONType
      end
    end
  end
end
