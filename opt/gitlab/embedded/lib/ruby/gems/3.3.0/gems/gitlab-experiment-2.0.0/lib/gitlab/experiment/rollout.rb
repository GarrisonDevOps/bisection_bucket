# frozen_string_literal: true

module Gitlab
  class Experiment
    module Rollout
      autoload :Percent, 'gitlab/experiment/rollout/percent.rb'
      autoload :Random, 'gitlab/experiment/rollout/random.rb'
      autoload :RoundRobin, 'gitlab/experiment/rollout/round_robin.rb'

      def self.resolve(klass, options = {})
        options ||= {}
        case klass
        when String
          Strategy.new(klass.classify.constantize, options)
        when Symbol
          Strategy.new("#{name}::#{klass.to_s.classify}".constantize, options)
        when Class
          Strategy.new(klass, options)
        else
          raise ArgumentError, "unable to resolve rollout from #{klass.inspect}"
        end
      end

      class Base
        attr_reader :experiment, :options

        delegate :cache, :id, to: :experiment

        def initialize(experiment, options = {})
          raise ArgumentError, 'you must provide an experiment instance' unless experiment.class <= Gitlab::Experiment

          @experiment = experiment
          @options = options
        end

        def enabled?
          true
        end

        def resolve
          validate! # allow the rollout strategy to validate itself

          # Control variants are cached alongside other variants, which is required
          # for `only_assigned: true` tracking to work for the control arm.
          execute_assignment
        end

        private

        def validate!
          # base is always valid
        end

        def execute_assignment
          behavior_names.first
        end

        def behavior_names
          experiment.behaviors.keys
        end
      end

      Strategy = Struct.new(:klass, :options) do
        def for(experiment)
          klass.new(experiment, options)
        end
      end
    end
  end
end
