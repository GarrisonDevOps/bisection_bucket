# frozen_string_literal: true

module Mutations
  module VirtualRegistries
    module Cache
      module Entry
        # rubocop:disable GraphQL/GraphqlName -- Base class needs no name.
        class Destroy < BaseMutation
          authorize :destroy_virtual_registry

          argument :id, GraphQL::Types::String,
            required: true,
            description: 'ID of the cache entry.'

          def resolve(id:)
            entry = authorized_find!(id: id)

            raise_resource_not_available_error! unless available?(entry)

            entry.pending_destruction!

            {
              cache_entry: entry,
              errors: errors_on_object(entry)
            }
          end

          private

          def find_object(id:)
            decoded_id = Base64.urlsafe_decode64(id)
            group_id, iid = decoded_id.split
            cache_entry_model
              .default
              .find_by_group_id_and_iid(group_id, iid)
          rescue ArgumentError
            nil
          end

          def cache_entry_model
            raise NotImplementedError, "#{self} does not implement #{__method__}"
          end

          def available?(_entry)
            raise NotImplementedError, "#{self} does not implement #{__method__}"
          end
        end
        # rubocop:enable GraphQL/GraphqlName
      end
    end
  end
end
