# frozen_string_literal: true

module Resolvers
  module Cd
    class ApplicationFlowDefinitionsResolver < BaseResolver
      max_page_size 20

      type ::Types::Cd::ApplicationFlowDefinitionType.connection_type, null: true

      alias_method :application, :object

      def resolve
        return unless Feature.enabled?(:ai_native_deploy, current_user)

        application.application_flow_definitions
      end
    end
  end
end
