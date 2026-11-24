# frozen_string_literal: true

module Gitlab
  class Experiment
    module TestBehaviors
      module Trackable
        private

        def manage_nested_stack
          TrackedStructure.push(self)
          super
        ensure
          TrackedStructure.pop
        end
      end

      class TrackedStructure
        include Singleton

        # dependency tracking
        @flat = {}
        @stack = []

        # structure tracking
        @tree = { name: nil, count: 0, children: {} }
        @node = @tree

        class << self
          def reset!
            # dependency tracking
            @flat = {}
            @stack = []

            # structure tracking
            @tree = { name: nil, count: 0, children: {} }
            @node = @tree
          end

          def hierarchy
            @tree[:children]
          end

          def dependencies
            @flat
          end

          def push(instance)
            # dependency tracking
            @flat[instance.name] = ((@flat[instance.name] || []) + @stack.map(&:name)).uniq
            @stack.push(instance)

            # structure tracking
            @last = @node
            @node = @node[:children][instance.name] ||= { name: instance.name, count: 0, children: {} }
            @node[:count] += 1
          end

          def pop
            # dependency tracking
            @stack.pop

            # structure tracking
            @node = @last
          end
        end
      end
    end
  end
end
