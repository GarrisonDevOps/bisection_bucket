# frozen_string_literal: true

module Ai
  module DuoWorkflow
    class RunnerValidator
      WORKFLOW_ID_VARIABLE = 'DUO_WORKFLOW_WORKFLOW_ID'

      # `container` is the project or group whose readiness or job is being checked.
      def initialize(runner, container, build: nil)
        @runner = runner
        @container = container
        @build = build
      end

      def valid?
        return false if gitlab_hosted_runner_required? && !gitlab_hosted_runner?
        return true unless Feature.enabled?(:duo_runner_restrictions, @container)

        # We only allow instance and top level group runners for Duo Agent Platform
        @runner.instance_type? ||
          (@runner.group_type? && @runner.groups.one? && @runner.groups.first.root?)
      end

      private

      # GitLab.com hosted runners, or a runner GitLab operates for a Dedicated tenant.
      # This relies on instance admins being unable to reset a hosted runner's token.
      def gitlab_hosted_runner?
        @runner.dot_com_gitlab_hosted? || @runner.gitlab_operated_hosted_runner?
      end

      # A gitlab_hosted_runner_only flow's job runs only on GitLab-hosted runners, except on
      # Self-Managed (see FoundationalFlow#gitlab_hosted_runner_required?). A job
      # whose workflow cannot be resolved is not treated as one: such jobs come from flow
      # triggers, while every gitlab_hosted_runner_only flow starts through
      # StartWorkflowService or ResumeWorkflowService, which always set
      # DUO_WORKFLOW_WORKFLOW_ID.
      def gitlab_hosted_runner_required?
        return false unless @build

        !!job_workflow&.foundational_flow&.gitlab_hosted_runner_required?
      end

      # The workload link is created after the pipeline, whose jobs are already
      # pending, so a runner can pick a job first. Rails also writes the workflow
      # ID into the job definition, which covers that window.
      def job_workflow
        @build.pipeline.workload&.latest_workflow || workflow_from_job_definition
      end

      def workflow_from_job_definition
        variable = @build.yaml_variables.find { |v| v[:key] == WORKFLOW_ID_VARIABLE }
        return unless variable

        workflow = ::Ai::DuoWorkflows::Workflow.find_by_id(variable[:value])
        workflow if workflow&.project_id == @build.project_id
      end
    end
  end
end
