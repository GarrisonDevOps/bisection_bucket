# frozen_string_literal: true

module Types
  module Ai
    module DuoWorkflows
      class WorkflowEnvironmentEnum < BaseEnum
        graphql_name 'WorkflowEnvironment'
        description 'The environment of a workflow.'

        ::Ai::DuoWorkflows::Workflow.environments.each_key do |mode|
          new_value = ::Ai::DuoWorkflows::Workflow::ENVIRONMENTS_DEPRECATIONS[mode]
          deprecated_options = if new_value
                                 {
                                   reason: :renamed,
                                   replacement: new_value.upcase,
                                   milestone: '18.6'
                                 }
                               end

          value mode.upcase, value: mode, description: "#{mode.titleize} environment", deprecated: deprecated_options
        end
      end
    end
  end
end
