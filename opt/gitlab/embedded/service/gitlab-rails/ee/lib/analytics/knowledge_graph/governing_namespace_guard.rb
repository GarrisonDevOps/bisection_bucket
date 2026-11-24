# frozen_string_literal: true

module Analytics
  module KnowledgeGraph
    module GoverningNamespaceGuard
      class RequiredError < StandardError
        attr_reader :contract

        def initialize(candidates)
          @contract = GoverningNamespaceError.new(candidates)

          super('Orbit billing namespace required')
        end
      end

      def self.ensure_selected!(user)
        return unless user
        return unless ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)
        return unless ::Feature.enabled?(:knowledge_graph_billing, user)
        return if user.user_preference.knowledge_graph_governing_namespace_with_fallback

        raise RequiredError.new(GoverningNamespaceFinder.for(user).candidates.to_a) # rubocop:disable Style/RaiseArgs -- avoid the candidates array reading like the exception message
      end
    end
  end
end
