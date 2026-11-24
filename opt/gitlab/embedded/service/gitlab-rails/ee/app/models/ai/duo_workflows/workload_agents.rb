# frozen_string_literal: true

module Ai
  module DuoWorkflows
    # The workspace agents a session's latest CI run received in DUO_WORKFLOW_AGENTS. StartWorkflowService always sets
    # the variable ('[]' when the agents are off), and ResumeWorkflowService carries it over to every later run, so the
    # job variables record exactly what each run got.
    class WorkloadAgents
      VARIABLE = 'DUO_WORKFLOW_AGENTS'

      def initialize(workflow)
        @workflow = workflow
      end

      # Nil when GitLab didn't send the run any agents: a session that runs in the Duo CLI, or a run that
      # Ai::FlowTriggers::RunService started.
      def list
        value = first_build&.yaml_variables&.find { |variable| variable[:key].to_s == VARIABLE }&.dig(:value)
        return if value.nil?

        agents = ::Gitlab::Json::SafeParser.parse(value)
        agents if agents.is_a?(Array)
      rescue JSON::ParserError
        nil
      end

      private

      attr_reader :workflow

      def first_build
        workflow.last_workload&.pipeline&.builds&.order(:id)&.first
      end
    end
  end
end
