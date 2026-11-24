# frozen_string_literal: true

module Mutations
  module VirtualRegistries
    module Upstream
      class Test < BaseMutation # rubocop:disable GraphQL/GraphqlName -- Base class needs no name.
        include Mutations::ResolvesGroup

        authorize :update_virtual_registry

        argument :group_path, ::GraphQL::Types::ID,
          required: false,
          description: 'Full path of the group to test the upstream registry against. ' \
            'Required when `id` is not provided.'

        argument :url, GraphQL::Types::String,
          required: false,
          description: 'URL of the upstream registry to test. ' \
            'Required when `GraphqlExplorerControllerid` is not provided.'

        argument :username, GraphQL::Types::String,
          required: false,
          description: 'Username for authenticating with the upstream registry. ' \
            'Used when `id` is not provided.'

        argument :password, GraphQL::Types::String,
          required: false,
          description: 'Password for authenticating with the upstream registry. ' \
            'Used when `id` is not provided.'

        field :success, GraphQL::Types::Boolean,
          null: false,
          description: 'Whether the upstream connectivity test was successful.'

        def ready?(id: nil, group_path: nil, url: nil, **args)
          unless id || (group_path && url)
            raise Gitlab::Graphql::Errors::ArgumentError,
              'Either id or groupPath and url are required'
          end

          super
        end

        # `find_upstream` resolves the upstream from `id` and ignores
        # `group_path` when both arguments are given. Granular token boundaries
        # are ORed, so drop `group_path` here to keep the boundary directives
        # (see the `boundaries:` declaration in subclasses) aligned with that
        # resolution order. Otherwise a token scoped to the `group_path` group
        # could act on an upstream that belongs to a different group.
        def authorized?(**args)
          args = args.except(:group_path) if args[:id]

          super
        end

        def resolve(**args)
          upstream = find_upstream(args)

          raise_resource_not_available_error! unless available?(upstream.group)

          if upstream.valid?
            test_result = upstream.test

            {
              success: test_result[:success],
              errors: Array.wrap(test_result[:result])
            }
          else
            {
              success: false,
              errors: errors_on_object(upstream)
            }
          end
        end

        private

        def find_upstream(args)
          if args[:id]
            authorized_find!(id: args[:id])
          else
            group = authorized_find!(group_path: args[:group_path])

            upstream_class.new(
              args.slice(:url, :username, :password).merge(
                group: group,
                name: ::VirtualRegistries::Upstream::TEST_UPSTREAM_NAME
              )
            )
          end
        end

        def available?(_)
          raise NotImplementedError, "#{self} does not implement #{__method__}"
        end

        def upstream_class
          raise NotImplementedError, "#{self} does not implement #{__method__}"
        end

        def find_object(group_path: nil, id: nil)
          if id
            GitlabSchema.object_from_id(id, expected_type: upstream_class)
          else
            resolve_group(full_path: group_path)
          end
        end

        def authorize!(object)
          raise_resource_not_available_error! unless object

          group = object.is_a?(Group) ? object : object.group

          raise_resource_not_available_error! unless authorized_resource?(group.virtual_registry_policy_subject)
        end
      end
    end
  end
end
