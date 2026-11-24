# frozen_string_literal: true

module Analytics
  module KnowledgeGraph
    class GoverningNamespaceError
      CODE = 'billing_namespace_required'

      def initialize(candidates)
        @candidates = candidates
      end

      def as_json(*)
        {
          code: CODE,
          message: message,
          deep_link: deep_link,
          candidates: formatted_candidates
        }
      end

      private

      attr_reader :candidates

      def message
        s_('Orbit|Select a default group in your preferences to run GitLab Orbit queries.')
      end

      def deep_link
        ::Gitlab::Routing.url_helpers.profile_preferences_url
      end

      def formatted_candidates
        candidates.map { |group| { id: group.id, name: group.name } }
      end
    end
  end
end
