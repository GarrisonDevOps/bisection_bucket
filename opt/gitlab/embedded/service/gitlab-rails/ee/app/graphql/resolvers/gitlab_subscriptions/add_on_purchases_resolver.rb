# frozen_string_literal: true

module Resolvers
  module GitlabSubscriptions
    class AddOnPurchasesResolver < BaseResolver
      include LooksAhead

      type [Types::GitlabSubscriptions::AddOnPurchaseType], null: true

      argument :namespace_id,
        type: ::Types::GlobalIDType[::Namespace],
        required: false,
        description: 'ID of namespace that the add-ons were purchased for.'

      def resolve_with_lookahead(namespace_id: nil)
        apply_lookahead(::GitlabSubscriptions::AddOnPurchase.active.by_namespace(namespace_id&.model_id))
      end

      private

      def unconditional_includes
        [:assigned_users]
      end
    end
  end
end
