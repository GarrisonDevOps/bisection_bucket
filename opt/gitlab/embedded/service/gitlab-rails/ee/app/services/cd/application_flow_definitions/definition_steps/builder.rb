# frozen_string_literal: true

module Cd
  module ApplicationFlowDefinitions
    module DefinitionSteps
      # Builds the static step tree of a flow definition, purely in memory: no
      # Cd::RolloutStep rows, no rollout required, no query. Environment names are
      # carried raw (not resolved to Cd::Environment records here) so
      # Types::Cd::DefinitionStepType can batch-resolve them across all flow
      # definitions in the response, avoiding one query per flow definition.
      class Builder
        def initialize(document:, flow_definition:)
          @document = document
          @flow_definition = flow_definition
        end

        def steps
          top_level_nodes.map { |path, _parent_path, step| to_definition_step(path, nil, step) }
        end

        private

        attr_reader :document, :flow_definition

        def top_level_nodes
          nodes_by_parent_path[nil] || []
        end

        def nodes_by_parent_path
          @nodes_by_parent_path ||= document.steps_with_paths.group_by { |_path, parent_path, _step| parent_path }
        end

        def to_definition_step(path, parent_path, step)
          children = (nodes_by_parent_path[path] || []).map do |child_path, _parent, child_step|
            to_definition_step(child_path, path, child_step)
          end

          ::Cd::ApplicationFlowDefinitions::DefinitionSteps::Step.new(
            path: path,
            parent_path: parent_path,
            step_type: step.type,
            name: step.name,
            params: step.params,
            environment_name: step.environment,
            organization_id: flow_definition.organization_id,
            steps: children,
            flow_definition: flow_definition
          )
        end
      end
    end
  end
end
