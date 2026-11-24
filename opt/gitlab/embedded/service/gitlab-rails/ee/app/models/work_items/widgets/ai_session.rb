# frozen_string_literal: true

module WorkItems
  module Widgets
    class AiSession < Base
      # Newest unfinished session of each given work item, one query for the ids and one for the
      # records, so the result stays bounded by the number of work items. Callers must not expose
      # more than the session's presence unless the user can read it.
      #
      # @param work_item_ids [Array<Integer>]
      # @return [Hash<Integer, Ai::DuoWorkflows::Workflow>] one entry per work item with an active session
      def self.latest_active_workflows_for(work_item_ids)
        workflows = ::Ai::DuoWorkflows::Workflow
          .for_issue(work_item_ids)
          .without_foundational_chat_agents
          .without_statuses(::Ai::DuoWorkflows::Workflow::TERMINAL_STATUSES + [:idle])
          .latest_per_issue
          .to_a

        ::Ai::DuoWorkflows::Workflow
          .with_preloaded_associations
          .id_in(workflows.map(&:id))
          .index_by(&:issue_id)
      end

      def duo_workflows
        work_item.duo_workflows.without_foundational_chat_agents.with_preloaded_associations
      end
    end
  end
end
