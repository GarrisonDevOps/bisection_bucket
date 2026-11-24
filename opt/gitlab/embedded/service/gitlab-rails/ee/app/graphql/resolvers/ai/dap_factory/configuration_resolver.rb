# frozen_string_literal: true

module Resolvers
  module Ai
    module DapFactory
      class ConfigurationResolver < BaseResolver
        alias_method :project, :object

        type ::Types::Ai::DapFactory::ConfigurationType, null: true

        authorize :read_code, :update_ai_flow_trigger
        authorizes_object!

        def resolve
          return unless ::Gitlab::Ai::SoftwareFactory.enabled?(project)

          ::Ai::DapFactory::ConfigurationFile.new(project)
        end
      end
    end
  end
end
