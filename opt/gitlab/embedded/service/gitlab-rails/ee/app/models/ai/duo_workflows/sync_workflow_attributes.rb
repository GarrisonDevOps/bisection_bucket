# frozen_string_literal: true

module Ai
  module DuoWorkflows
    module SyncWorkflowAttributes
      extend ActiveSupport::Concern

      included do
        before_validation :ensure_container

        private

        def ensure_container
          return unless workflow

          if workflow.project_level?
            self.project_id = workflow.project_id
          elsif workflow.namespace_level?
            self.namespace_id = workflow.namespace_id
          end
        end
      end
    end
  end
end
