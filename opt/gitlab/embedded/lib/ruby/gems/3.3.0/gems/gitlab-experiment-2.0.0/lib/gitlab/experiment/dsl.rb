# frozen_string_literal: true

module Gitlab
  class Experiment
    module Dsl
      def self.include_in(klass, with_helper: false)
        klass.include(self).tap { |base| base.helper_method(:experiment) if with_helper }
      end

      # An explicit `request:` keyword argument always takes precedence; when
      # present, no auto-detection runs.
      #
      # Otherwise, `request` is auto-detected through implicit_experiment_request in this order:
      #   1. A `request` method on `self` (the controller pattern).
      #   2. A `@request` instance variable on `self` (the service pattern).
      #
      # Callers with `request` as a pure local variable should pass
      # `request: request` explicitly.
      def experiment(name, variant_name = nil, **context, &block)
        raise ArgumentError, 'name is required' if name.nil?

        context[:request] ||= implicit_experiment_request

        base = Configuration.base_class.constantize
        klass = base.constantize(name) || base

        instance = klass.new(name, variant_name, **context, &block)
        return instance unless block

        instance.context.frozen? ? instance.run : instance.tap(&:run)
      end

      private

      def implicit_experiment_request
        if respond_to?(:request)
          request
        elsif instance_variable_defined?(:@request)
          instance_variable_get(:@request)
        end
      end
    end
  end
end
