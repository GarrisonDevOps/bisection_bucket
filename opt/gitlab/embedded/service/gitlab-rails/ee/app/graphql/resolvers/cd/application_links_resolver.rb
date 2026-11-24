# frozen_string_literal: true

module Resolvers
  module Cd
    class ApplicationLinksResolver < BaseResolver
      include LooksAhead

      type ::Types::Cd::ApplicationLinkType.connection_type, null: true

      alias_method :application, :object

      def resolve_with_lookahead(**)
        return unless Feature.enabled?(:ai_native_deploy, current_user)

        apply_lookahead(application.application_links)
      end
    end
  end
end
