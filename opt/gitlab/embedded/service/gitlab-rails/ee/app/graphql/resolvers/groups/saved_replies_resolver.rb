# frozen_string_literal: true

module Resolvers
  module Groups
    class SavedRepliesResolver < BaseResolver
      include Gitlab::Graphql::Authorize::AuthorizeResource

      extension ::Gitlab::Graphql::Limit::FieldCallCount, limit: 1

      authorizes_object!

      authorize :read_saved_reply

      argument :include_ancestor_groups,
        GraphQL::Types::Boolean,
        required: false,
        default_value: false,
        description: 'Include saved replies from parent groups.'

      type ::Types::Groups::SavedReplyType, null: true

      def resolve(**args)
        ::Groups::SavedRepliesFinder.new(object, args).execute
      end
    end
  end
end
