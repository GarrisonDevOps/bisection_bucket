# frozen_string_literal: true

module Resolvers
  module Cd
    class DeploymentsResolver < BaseResolver
      include LooksAhead

      type ::Types::Cd::DeploymentType.connection_type, null: true

      alias_method :rollout_environment, :object

      def resolve_with_lookahead(**)
        return unless Feature.enabled?(:ai_native_deploy, current_user)

        apply_lookahead(rollout_environment.deployments)
      end

      private

      # service is always required to authorize each deployment (the policy
      # delegates Cd::Deployment -> service -> application), so preload it
      # regardless of the requested fields to avoid an N+1 during authorization.
      def unconditional_includes
        [:service]
      end

      def preloads
        { deployment_transitions: [:deployment_transitions] }
      end
    end
  end
end
