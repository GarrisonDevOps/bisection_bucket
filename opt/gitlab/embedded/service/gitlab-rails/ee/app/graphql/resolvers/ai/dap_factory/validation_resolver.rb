# frozen_string_literal: true

module Resolvers
  module Ai
    module DapFactory
      class ValidationResolver < BaseResolver
        alias_method :project, :object

        type ::Types::Ai::DapFactory::ValidationResultType, null: true

        authorize :update_ai_flow_trigger
        authorizes_object!
        authorize_granular_token permissions: :update_ai_flow_trigger, boundary: :itself, boundary_type: :project

        argument :content, GraphQL::Types::String,
          required: true,
          description: 'Content of a DAP Software Factory configuration file.'

        def resolve(content:)
          return unless ::Gitlab::Ai::SoftwareFactory.enabled?(project)

          ::Gitlab::Ai::DapFactory::Validator.new(content: content, project: project).execute
        end
      end
    end
  end
end
