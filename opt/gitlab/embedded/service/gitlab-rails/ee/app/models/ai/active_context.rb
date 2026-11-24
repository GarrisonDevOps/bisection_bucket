# frozen_string_literal: true

module Ai
  module ActiveContext
    class << self
      def paused?
        return false unless ::ActiveContext.indexing?

        Gitlab::CurrentSettings.active_context_indexing_paused?
      end

      def semantic_search_available?
        License.ai_features_available? &&
          ::Gitlab::CurrentSettings.duo_features_enabled?
      end

      def gitlab_selects_embedding_model?
        # We need to check the instance type, not a specific feature
        # For SaaS, ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions) works
        # For Dedicated, there is no equivalent check, so we have to use Gitlab::Dedicated.dedicated_instance?
        ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions) ||
          ::Gitlab::Dedicated.dedicated_instance? || # rubocop: disable Gitlab/AvoidGitlabDedicatedInstanceChecks -- see comment above
          !::Gitlab::AiGateway.has_self_hosted_ai_gateway?
      end

      def user_selects_embedding_model?
        !gitlab_selects_embedding_model?
      end
    end
  end
end
