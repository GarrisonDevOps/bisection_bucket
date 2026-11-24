# frozen_string_literal: true

module Resolvers
  module Ai
    module DuoWorkflows
      class PipelineWorkflowsResolver < BaseResolver
        type ::Types::Ai::DuoWorkflows::WorkflowType.connection_type, null: true

        alias_method :pipeline, :object

        def resolve
          return unless pipeline.project.licensed_feature_available?(:ai_workflows)

          BatchLoader::GraphQL.for(pipeline).batch(
            default_value: [], key: :duo_workflows_for_pipeline
          ) do |pipelines, loader|
            workflows_by_pipeline_id = ::Ai::DuoWorkflows::Workflow.grouped_by_pipeline_id(pipelines.map(&:id))

            # One query per association for the whole batch, so the per-session user,
            # namespace and catalog item fields do not query once per node.
            ActiveRecord::Associations::Preloader.new(
              records: workflows_by_pipeline_id.values.flatten,
              associations: [:user, :namespace, { ai_catalog_item_version: :item }]
            ).call

            pipelines.each do |batched_pipeline|
              workflows = workflows_by_pipeline_id.fetch(batched_pipeline.id, [])

              # Every workflow linked to a pipeline belongs to that pipeline's project, so
              # hand each node the project we already have. That keeps the per-node
              # read_duo_workflow check off a project load, and licensed_feature_available?
              # memoizes once on the shared instance.
              workflows.each { |workflow| workflow.association(:project).target = batched_pipeline.project }

              loader.call(batched_pipeline, workflows)
            end
          end
        end
      end
    end
  end
end
