# frozen_string_literal: true

module Resolvers
  module Ai
    class GitlabCreditsUnavailableReasonResolver < BaseResolver
      include Gitlab::Graphql::Authorize::AuthorizeResource

      authorize :read_namespace

      type ::Types::Ai::CreditsDenialReasonEnum, null: true

      description 'Reason GitLab credits are unavailable. Returns "usage_billing_forbidden" when usage ' \
        'billing is not available for the account, and "namespace_missing" when there is no namespace ' \
        'to bill the usage to. Returns null when credits are available or the unavailability reason ' \
        'is not recognized.'

      argument :namespace_id,
        ::Types::GlobalIDType[::Namespace],
        required: false,
        description: 'Global ID of the namespace to check credits for.'

      def resolve(namespace_id: nil)
        return unless current_user

        namespace = authorized_find!(id: namespace_id) if namespace_id

        ::Gitlab::Llm::DuoChat.new(user: current_user, container: namespace).credits_unavailable_reason&.to_s
      end
    end
  end
end
