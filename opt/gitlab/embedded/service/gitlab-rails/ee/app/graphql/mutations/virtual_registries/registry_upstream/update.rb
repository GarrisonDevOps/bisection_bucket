# frozen_string_literal: true

module Mutations
  module VirtualRegistries
    module RegistryUpstream
      # rubocop:disable GraphQL/GraphqlName -- This is a base mutation so name is not needed here
      class Update < BaseMutation
        authorize :update_virtual_registry

        argument :position, GraphQL::Types::Int,
          required: true,
          description: 'Priority order of an upstream within a virtual registry.'

        def resolve(id:, position:)
          registry_upstream = authorized_find!(id: id)

          raise_resource_not_available_error! unless enabled?(registry_upstream)

          if registry_upstream.update_position(position)
            {
              registry_upstream: registry_upstream,
              errors: []
            }
          else
            {
              registry_upstream: nil,
              errors: errors_on_object(registry_upstream)
            }
          end
        end

        private

        def enabled?(_)
          raise NotImplementedError, "#{self} does not implement #{__method__}"
        end
      end
      # rubocop:enable GraphQL/GraphqlName
    end
  end
end
