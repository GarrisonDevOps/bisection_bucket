# frozen_string_literal: true

module Resolvers
  module SecurityOrchestration
    class SecurityPolicyProjectSuggestionsResolver < BaseResolver
      include ::GitlabSubscriptions::SubscriptionHelper

      type Types::ProjectType, null: true

      description 'Suggest security policy projects by search term'

      argument :search, GraphQL::Types::String,
        required: true,
        description: "Search query for projects' full paths."

      argument :only_linked, GraphQL::Types::Boolean,
        required: false,
        default_value: false,
        description: 'Whether to suggest only projects already linked as security policy projects.'

      max_page_size ::Security::SecurityPolicyProjectsFinder::SUGGESTION_LIMIT

      def resolve(**args)
        args[:search_globally] = !gitlab_com_subscription?

        ::Security::SecurityPolicyProjectsFinder
          .new(container: object, current_user: current_user, params: args)
          .execute
      end
    end
  end
end
