# frozen_string_literal: true

module Resolvers
  module Cd
    class ArtifactSourcesResolver < BaseResolver
      include LooksAhead

      type ::Types::Cd::ArtifactSourceType.connection_type, null: true

      max_page_size 20

      alias_method :service, :object

      def resolve_with_lookahead(**)
        return unless Feature.enabled?(:ai_native_deploy, current_user)

        apply_lookahead(service.artifact_sources)
      end

      private

      def preloads
        { versions: [:versions] }
      end
    end
  end
end
