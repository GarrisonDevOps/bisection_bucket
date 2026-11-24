# frozen_string_literal: true

module Resolvers
  module Ai
    class UserAvailableFeaturesResolver < BaseResolver
      type [::GraphQL::Types::String], null: false

      def resolve
        return [] unless current_user
        return [] unless duo_chat_enabled?

        # Categories without a unit primitive are dropped before the name is built rather
        # than left to `allowed_to_use?`: `check_amazon_q_feature` answers `:chat` before
        # the unit primitive is validated, so with Amazon Q connected a name the cloud
        # connector does not define would be reported as available.
        categories = ::Ai::AdditionalContext::DUO_CHAT_CONTEXT_CATEGORIES.values -
          ::Ai::AdditionalContext::DUO_CHAT_CONTEXT_CATEGORIES_WITHOUT_UNIT_PRIMITIVE

        categories
          .select { |category| category_enabled?(category) }
          .map { |category| "include_#{category}_context" }
          .select do |unit_primitive|
            current_user.allowed_to_use?(:chat, unit_primitive_name: unit_primitive.to_sym)
          end
      end

      private

      def duo_chat_enabled?
        # ee/app/graphql/resolvers/ai/user_chat_access_resolver.rb we have the same pattern
        ::Gitlab::Llm::Chain::Utils::ChatAuthorizer.user(user: current_user).allowed?
      end

      def category_enabled?(category)
        already_enabled_context = %w[file snippet user_rule agent_user_environment repository directory terminal].freeze
        return true if already_enabled_context.include?(category)

        Feature.enabled?(:"duo_include_context_#{category}", current_user)
      end
    end
  end
end
