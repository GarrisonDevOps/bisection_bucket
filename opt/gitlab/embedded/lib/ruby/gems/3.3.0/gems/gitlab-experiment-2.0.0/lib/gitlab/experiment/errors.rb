# frozen_string_literal: true

module Gitlab
  class Experiment
    Error = Class.new(StandardError)
    InvalidRolloutRules = Class.new(Error)
    UnregisteredExperiment = Class.new(Error)
    ExistingBehaviorError = Class.new(Error)
    BehaviorMissingError = Class.new(Error)

    class NestingError < Error
      def initialize(experiment:, nested_experiment:)
        messages = []
        experiments = [nested_experiment, experiment]

        callers = caller_locations
        callers.select.with_index do |caller, index|
          next if caller.label != 'experiment'

          messages << "  #{experiments[messages.length].name} initiated by #{callers[index + 1]}"
        end

        messages << ["unable to nest #{nested_experiment.name} within #{experiment.name}:"]

        super(messages.reverse.join("\n"))
      end
    end
  end
end
