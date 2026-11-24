# frozen_string_literal: true

module Resolvers
  module Cd
    class ApplicationEnvironmentsResolver < BaseResolver
      include LooksAhead

      type ::Types::Cd::EnvironmentType.connection_type, null: true

      alias_method :application, :object

      def resolve_with_lookahead(**)
        return unless Feature.enabled?(:ai_native_deploy, current_user)

        apply_lookahead(application.environments)
      end
    end
  end
end
