# frozen_string_literal: true

module Resolvers
  module Cd
    class EnvironmentDriverBindingsResolver < BaseResolver
      type ::Types::Cd::EnvironmentDriverBindingType.connection_type, null: true

      alias_method :environment, :object

      def resolve
        return unless Feature.enabled?(:ai_native_deploy, current_user)

        environment.environment_driver_bindings
      end
    end
  end
end
