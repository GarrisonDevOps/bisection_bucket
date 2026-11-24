# frozen_string_literal: true

module Resolvers
  module Cd
    class RolloutEnvironmentsResolver < BaseResolver
      include LooksAhead

      type ::Types::Cd::RolloutEnvironmentType.connection_type, null: true

      max_page_size 20

      def resolve_with_lookahead(**)
        return unless Feature.enabled?(:ai_native_deploy, current_user)

        apply_lookahead(object.rollout_environments)
      end

      private

      def unconditional_includes
        [:rollout]
      end

      def preloads
        { deployments: [:deployments] }
      end
    end
  end
end
