# frozen_string_literal: true

module Mutations
  module VirtualRegistries
    module Cache
      # rubocop:disable GraphQL/GraphqlName -- Base class needs no name.
      class Destroy < BaseMutation
        authorize :destroy_virtual_registry

        def resolve(id:)
          object = authorized_find!(id: id)

          raise_resource_not_available_error! unless available?(object)

          object.purge_cache!

          {
            response_field_name => object,
            errors: errors_on_object(object)
          }
        end

        private

        def available?(_object)
          raise NotImplementedError, "#{self} does not implement #{__method__}"
        end

        def response_field_name
          raise NotImplementedError, "#{self} does not implement #{__method__}"
        end
      end
      # rubocop:enable GraphQL/GraphqlName
    end
  end
end
