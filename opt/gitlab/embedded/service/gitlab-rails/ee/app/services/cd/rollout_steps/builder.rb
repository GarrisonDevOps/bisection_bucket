# frozen_string_literal: true

module Cd
  module RolloutSteps
    # Builds one unsaved Cd::RolloutStep per node in a flow definition's step
    # tree, ready for bulk insertion by Cd::Rollouts::CreateService at rollout
    # creation time (rather than at start).
    class Builder
      def initialize(rollout:, document:, rollout_environments_by_name:)
        @rollout = rollout
        @document = document
        @rollout_environments_by_name = rollout_environments_by_name
      end

      def steps
        # One timestamp for the whole batch: bulk_insert! skips the AR timestamp
        # callback, and rows created together should carry identical created_at.
        timestamp = Time.current

        document.steps_with_paths.map do |path, parent_path, step|
          ::Cd::RolloutStep.new(
            organization: rollout.organization,
            rollout: rollout,
            rollout_environment: rollout_environment_for(step),
            path: path,
            parent_path: parent_path,
            step_type: step.type,
            name: step.name,
            params: step.params,
            created_at: timestamp,
            updated_at: timestamp
          )
        end
      end

      private

      attr_reader :rollout, :document, :rollout_environments_by_name

      def rollout_environment_for(step)
        rollout_environments_by_name[step.environment]
      end
    end
  end
end
