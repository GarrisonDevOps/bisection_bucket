# frozen_string_literal: true

module Resolvers
  module WebHooks
    class GroupHooksResolver < BaseResolver
      include ::LooksAhead
      include Gitlab::Graphql::Authorize::AuthorizeResource

      authorizes_object!
      authorize :read_webhook

      type Types::WebHooks::GroupHookType.connection_type, null: true

      alias_method :group, :object

      when_single do
        argument :id, Types::GlobalIDType[::GroupHook],
          required: true,
          description: 'ID of the group webhook.'
      end

      def resolve(**args)
        hooks = group.hooks

        return hooks unless args[:id].present?

        hooks.id_in(args[:id].model_id)
      end
    end
  end
end
