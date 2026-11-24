# frozen_string_literal: true

module Resolvers
  module Ai
    class GitlabCreditsAvailableResolver < BaseResolver
      include Gitlab::Graphql::Authorize::AuthorizeResource

      authorize :read_namespace

      type GraphQL::Types::Boolean, null: false

      description 'Check whether GitLab credits are available for the current user.'

      argument :namespace_id,
        ::Types::GlobalIDType[::Namespace],
        required: false,
        description: 'Global ID of the namespace to check credits for.'

      def resolve(namespace_id: nil)
        return false unless current_user

        namespace = authorized_find!(id: namespace_id) if namespace_id

        ::Gitlab::Llm::DuoChat.new(user: current_user, container: namespace).credits_available?
      end

      private

      def find_object(id:)
        GitlabSchema.find_by_gid(id)
      end
    end
  end
end
