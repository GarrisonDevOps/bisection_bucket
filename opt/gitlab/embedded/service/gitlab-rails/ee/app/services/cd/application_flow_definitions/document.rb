# frozen_string_literal: true

module Cd
  module ApplicationFlowDefinitions
    # Takes a parsed Hash rather than YAML because callers disagree on what a parse
    # failure means: Cd::Rollouts::CreateService raises, FlowDefinitionValidator does not.
    class Document
      STAGE_STEP_TYPE = 'com.gitlab.cd.steps.stage'

      # Prefix, not a list, so an engine release adding a common step needs no change here.
      ENGINE_STEP_TYPE_PREFIX = 'com.gitlab.cd.steps.'

      NODE_KEYS = %w[type name environment steps].freeze

      Step = Struct.new(:type, :name, :environment, :params, keyword_init: true)

      def initialize(parsed)
        @parsed = parsed
      end

      # One level of unrolling: stages do not nest (cf. _leaf_steps in main.star).
      def leaf_steps
        @leaf_steps ||= top_level_steps.flat_map { |step| stage?(step) ? nested_steps(step) : [step] }
      end

      # Engine-owned steps are excluded: they appear in no driver's steps schema.
      def driver_steps
        leaf_steps.reject { |step| engine_step?(step) }
      end

      def environment_names
        leaf_steps.filter_map { |step| step['environment'] }.uniq
      end

      # Every node (including stage containers), paired with its path
      # ("0", "0.0", ...) and parent path (nil at top level) -- one Cd::RolloutStep
      # per node, addressable by position.
      def steps_with_paths
        @steps_with_paths ||= top_level_steps.each_with_index.flat_map do |step, index|
          path = index.to_s
          node = [path, nil, to_step(step)]
          stage?(step) ? [node, *nested_steps_with_paths(step, path)] : [node]
        end
      end

      private

      attr_reader :parsed

      def top_level_steps
        return [] unless parsed.is_a?(Hash)

        Array(parsed['steps']).grep(Hash)
      end

      def nested_steps(stage)
        Array(stage['steps']).grep(Hash)
      end

      def nested_steps_with_paths(stage, parent_path)
        nested_steps(stage).each_with_index.map do |step, index|
          ["#{parent_path}.#{index}", parent_path, to_step(step)]
        end
      end

      def to_step(step)
        Step.new(type: step['type'], name: step['name'], environment: step['environment'],
          params: step.except(*NODE_KEYS).presence)
      end

      def stage?(step)
        step['type'] == STAGE_STEP_TYPE
      end

      def engine_step?(step)
        step['type'].to_s.start_with?(ENGINE_STEP_TYPE_PREFIX)
      end
    end
  end
end
