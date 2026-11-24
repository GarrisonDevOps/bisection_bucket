# frozen_string_literal: true

module Mutations
  module VirtualRegistries
    module Registry
      # rubocop:disable GraphQL/GraphqlName -- This is a base mutation so name is not needed here
      class Update < BaseMutation
        authorize :update_virtual_registry

        argument :id, ::GraphQL::Types::ID,
          required: true,
          description: 'ID of the virtual registry.'

        argument :name, ::GraphQL::Types::String,
          required: false,
          description: 'Name of virtual registry.'

        argument :description, ::GraphQL::Types::String,
          required: false,
          description: 'Description of the virtual registry.'

        def resolve(id:, **args)
          registry = authorized_find!(id: id)

          raise_resource_not_available_error! unless virtual_registry_available?(registry.group)

          result = service_class.new(registry: registry, current_user: current_user, params: args).execute

          if result.status == :success
            {
              registry: result.payload,
              errors: []
            }
          else
            {
              registry: nil,
              errors: result.errors
            }
          end
        end

        def virtual_registry_available?(group)
          raise NotImplementedError, 'Subclasses must implement virtual_registry_available?'
        end
      end
      # rubocop:enable GraphQL/GraphqlName
    end
  end
end
