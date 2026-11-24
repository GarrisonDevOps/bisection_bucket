# frozen_string_literal: true

module Ai
  module DuoWorkflows
    module WorkflowTokenScope
      PREFIX = /\Aduo_workflow:/
      PATTERN = /\Aduo_workflow:(\d+)\z/

      module_function

      def for(workflow_id)
        workflow_id ? ["duo_workflow:#{Integer(workflow_id)}"] : []
      end

      def workflow_id_from(scopes)
        bound = Array(scopes).map(&:to_s).grep(PREFIX)
        return unless bound.one?

        bound.first[PATTERN, 1]&.to_i
      end

      def bound?(scopes)
        Array(scopes).any? { |scope| PREFIX.match?(scope.to_s) }
      end

      def allows_workflow?(scopes, workflow_id)
        bound = Array(scopes).map(&:to_s).grep(PREFIX)

        bound.empty? || bound == self.for(workflow_id)
      end

      def without(scopes)
        Array(scopes).reject { |scope| PREFIX.match?(scope.to_s) }
      end
    end
  end
end
