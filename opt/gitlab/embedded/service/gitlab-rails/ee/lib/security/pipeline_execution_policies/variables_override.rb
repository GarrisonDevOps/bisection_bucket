# frozen_string_literal: true

module Security
  module PipelineExecutionPolicies
    class VariablesOverride
      def initialize(variables_override)
        @variables_override = variables_override || {}
      end

      def allowed
        variables_override[:allowed]
      end

      def exceptions
        variables_override[:exceptions] || []
      end

      private

      attr_reader :variables_override
    end
  end
end
