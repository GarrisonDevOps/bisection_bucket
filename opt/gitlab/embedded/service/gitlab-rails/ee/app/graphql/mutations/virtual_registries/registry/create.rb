# frozen_string_literal: true

module Mutations
  module VirtualRegistries
    module Registry
      # rubocop:disable GraphQL/GraphqlName -- This is a base mutation so name is not needed here
      class Create < BaseMutation
        include Mutations::ResolvesGroup

        authorize :create_virtual_registry

        argument :group_path, ::GraphQL::Types::ID,
          required: false,
          description: 'Full path of the group with which the resource is associated.'

        argument :name, ::GraphQL::Types::String,
          required: true,
          description: 'Name of virtual registry.'

        argument :description, ::GraphQL::Types::String,
          required: false,
          description: 'Description of the virtual registry.'

        def resolve(group_path:, **args)
          group = authorized_find!(group_path: group_path)

          result = service_class.new(group: group, current_user: current_user, params: args).execute

          raise_resource_not_available_error! if result.reason == :unavailable

          if result.status == :success
            {
              registry: result.payload,
              errors: []
            }
          else
            {
              registry: nil,
              errors: result.message
            }
          end
        end

        private

        def find_object(group_path:)
          resolve_group(full_path: group_path)
        end

        def authorize!(group)
          raise_resource_not_available_error! unless authorized_resource?(group.virtual_registry_policy_subject)
        end
      end
      # rubocop:enable GraphQL/GraphqlName
    end
  end
end
