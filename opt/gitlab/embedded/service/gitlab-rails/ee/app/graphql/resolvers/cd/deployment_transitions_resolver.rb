# frozen_string_literal: true

module Resolvers
  module Cd
    class DeploymentTransitionsResolver < BaseResolver
      type ::Types::Cd::DeploymentTransitionType.connection_type, null: true

      alias_method :deployment, :object

      def resolve
        return unless Feature.enabled?(:ai_native_deploy, current_user)

        deployment.deployment_transitions
      end
    end
  end
end
