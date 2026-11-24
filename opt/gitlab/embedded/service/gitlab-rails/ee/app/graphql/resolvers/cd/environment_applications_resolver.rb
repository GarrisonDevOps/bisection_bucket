# frozen_string_literal: true

module Resolvers
  module Cd
    class EnvironmentApplicationsResolver < BaseResolver
      type ::Types::Cd::EnvironmentApplicationType.connection_type, null: true

      alias_method :environment, :object

      EnvironmentApplication = Struct.new(:application, :service_environment_healths)

      def resolve
        return unless Feature.enabled?(:ai_native_deploy, current_user)

        grouped = ::Cd::ServiceEnvironmentHealth.service_environment_healths_by_application(environment)

        grouped.each_value.map do |healths|
          EnvironmentApplication.new(healths.first.service.application, healths)
        end
      end
    end
  end
end
