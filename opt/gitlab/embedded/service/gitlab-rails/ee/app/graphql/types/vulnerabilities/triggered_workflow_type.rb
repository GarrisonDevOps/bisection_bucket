# frozen_string_literal: true

module Types
  module Vulnerabilities
    class TriggeredWorkflowType < BaseObject
      graphql_name 'VulnerabilityTriggeredWorkflow'
      description 'Represents a triggered workflow for a vulnerability'

      authorize :read_vulnerability

      field :workflow_name, ::Types::Vulnerabilities::TriggeredWorkflowNameEnum, null: false,
        description: 'Name of the workflow.'

      field :workflow, ::Types::Ai::DuoWorkflows::WorkflowType, null: true,
        description: 'Associated workflow details.'

      def workflow
        Gitlab::Graphql::Loaders::BatchModelLoader.new(::Ai::DuoWorkflows::Workflow, object.workflow_id).find
      end
    end
  end
end
