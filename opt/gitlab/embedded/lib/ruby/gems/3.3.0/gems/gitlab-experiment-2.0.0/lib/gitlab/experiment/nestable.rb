# frozen_string_literal: true

module Gitlab
  class Experiment
    module Nestable
      extend ActiveSupport::Concern

      included do
        set_callback :run, :around, :manage_nested_stack
      end

      def nest_experiment(nested_experiment)
        instance_exec(nested_experiment, &Configuration.nested_behavior)
      end

      private

      def manage_nested_stack
        Stack.push(self)
        yield
      ensure
        Stack.pop
      end

      class Stack
        include Singleton

        delegate :pop, :length, :size, :[], to: :stack

        class << self
          delegate :pop, :push, :length, :size, :[], to: :instance
        end

        def initialize
          @thread_key = "#{self.class};#{object_id}".to_sym
        end

        def push(instance)
          stack.last&.nest_experiment(instance)
          stack.push(instance)
        end

        private

        def stack
          Thread.current[@thread_key] ||= []
        end
      end
    end
  end
end
