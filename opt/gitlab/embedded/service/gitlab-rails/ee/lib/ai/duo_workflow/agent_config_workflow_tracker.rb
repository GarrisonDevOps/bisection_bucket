# frozen_string_literal: true

module Ai
  module DuoWorkflow
    class AgentConfigWorkflowTracker
      CACHE_TTL = 7.days

      def initialize(project)
        @project = project
      end

      def track(workflow)
        Rails.cache.write(cache_key, workflow.id, expires_in: CACHE_TTL)
      end

      def active_workflow
        workflow = tracked_workflow
        return unless workflow&.created? || workflow&.running?

        workflow
      end

      private

      attr_reader :project

      def tracked_workflow
        cached_id = Rails.cache.read(cache_key)
        return unless cached_id

        workflow = ::Ai::DuoWorkflows::Workflow.find_in_project(project, cached_id)
        Rails.cache.delete(cache_key) unless workflow

        workflow
      end

      def cache_key
        ['duo_agent_config_workflow', project.id]
      end
    end
  end
end
