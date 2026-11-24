# frozen_string_literal: true

module Mutations
  module VirtualRegistries
    module Registry
      module Upstream
        # rubocop:disable GraphQL/GraphqlName -- This is a base mutation so name is not needed here
        class Destroy < BaseMutation
          authorize :destroy_virtual_registry

          def resolve(upstream_id:)
            registry_upstream = authorized_find!(id: upstream_id)

            result = service_class.new(
              registry_upstream: registry_upstream,
              current_user: current_user
            ).execute

            raise_resource_not_available_error! if result.reason == :unavailable

            if result.status == :success
              {
                registry_upstream: result.payload,
                errors: []
              }
            else
              {
                registry_upstream: nil,
                errors: result.message
              }
            end
          end

          private

          def service_class
            raise NotImplementedError, "#{self} does not implement #{__method__}"
          end
        end
        # rubocop:enable GraphQL/GraphqlName
      end
    end
  end
end
