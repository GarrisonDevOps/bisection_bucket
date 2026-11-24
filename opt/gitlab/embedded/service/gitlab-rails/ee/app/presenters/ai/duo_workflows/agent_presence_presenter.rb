# frozen_string_literal: true

module Ai
  module DuoWorkflows
    class AgentPresencePresenter < WorkflowPresenter
      def session_id
        workflow.id
      end

      def agent_catalog_web_path
        item = workflow.ai_catalog_item_version&.item
        return unless item

        url_builder.build(item, only_path: true)
      end
    end
  end
end
