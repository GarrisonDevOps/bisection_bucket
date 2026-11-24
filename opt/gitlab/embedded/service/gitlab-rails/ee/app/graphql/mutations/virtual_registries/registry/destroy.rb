# frozen_string_literal: true

module Mutations
  module VirtualRegistries
    module Registry
      # rubocop:disable GraphQL/GraphqlName -- Base class needs no name.
      class Destroy < BaseMutation
        authorize :destroy_virtual_registry

        def resolve(id:)
          registry = authorized_find!(id: id)

          raise_resource_not_available_error! unless available?(registry)

          registry.destroy

          {
            registry: registry.destroyed? ? registry : nil,
            errors: errors_on_object(registry)
          }
        end

        private

        def available?(_registry)
          raise NotImplementedError, "#{self} does not implement #{__method__}"
        end
      end
      # rubocop:enable GraphQL/GraphqlName
    end
  end
end
