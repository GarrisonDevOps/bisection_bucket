# frozen_string_literal: true

module Cd
  module ApplicationFlowDefinitions
    module DefinitionSteps
      # One node of a flow definition's static step tree, computed on read
      # (see Builder) rather than persisted -- unlike Cd::RolloutStep, this
      # carries no runtime fields (state, timestamps, error) since nothing has
      # run yet. environment_name/organization_id (rather than a resolved
      # Cd::Environment) let Types::Cd::DefinitionStepType batch-resolve
      # environments across every node of every flow definition in a response,
      # instead of this builder querying once per flow definition. flow_definition
      # is carried on every node (not exposed over GraphQL) purely so StepPolicy
      # has a subject to delegate authorization to.
      Step = Struct.new(:path, :parent_path, :step_type, :name, :params, :environment_name, :organization_id,
        :steps, :flow_definition, keyword_init: true)
    end
  end
end
