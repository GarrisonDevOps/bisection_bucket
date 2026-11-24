# frozen_string_literal: true

module Mutations
  module VirtualRegistries
    module Upstream
      class Destroy < BaseMutation # rubocop:disable GraphQL/GraphqlName -- Base class needs no name.
        authorize :destroy_virtual_registry

        def resolve(id:)
          upstream = authorized_find!(id: id)

          result = service_class.new(upstream: upstream, current_user: current_user).execute

          raise_resource_not_available_error! if result.reason == :unavailable

          if result.status == :success
            {
              upstream: result.payload,
              errors: []
            }
          else
            {
              upstream: nil,
              errors: result.message
            }
          end
        end

        private

        def service_class
          raise NotImplementedError, "#{self} does not implement #{__method__}"
        end
      end
    end
  end
end
