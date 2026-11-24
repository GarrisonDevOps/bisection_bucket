# frozen_string_literal: true

module Resolvers
  module Ai
    class DuoDefaultNamespaceCandidatesResolver < BaseResolver
      include Gitlab::Graphql::Authorize::AuthorizeResource

      type Types::NamespaceType.connection_type, null: true

      def resolve
        return Namespace.none unless current_user

        current_user.user_preference.duo_default_namespace_candidates
      end
    end
  end
end
