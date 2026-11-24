# frozen_string_literal: true

module Vulnerabilities
  module BulkDuoWorkflow
    module StateKeys
      KEY_PREFIX = 'vulnerabilities:bulk_duo_workflow'

      def self.current_execution_key(project_id:, workflow:)
        "#{KEY_PREFIX}:{#{project_id}:#{workflow}}:current"
      end

      def self.latest_execution_key(project_id:, workflow:)
        "#{KEY_PREFIX}:{#{project_id}:#{workflow}}:latest"
      end

      private

      attr_reader :execution_id, :project_id, :workflow

      def key(type)
        "#{KEY_PREFIX}:{#{project_id}:#{workflow}}:#{execution_id}:#{type}"
      end

      def stage_key(index)
        key("pending:stage:#{index}")
      end
    end
  end
end
