# frozen_string_literal: true

module AuditEvents
  module AiAuditEvents
    class Finder
      # rubocop:disable CodeReuse/Finder -- Dispatches to a PG- or ClickHouse-backed finder
      # @param workflow [Ai::DuoWorkflows::Workflow]
      # @param created_after [Time, nil] excludes events created before it, which lets both stores prune partitions
      def initialize(workflow:, created_after: nil)
        @workflow = workflow
        @created_after = created_after
      end

      def execute
        if ::Gitlab::ClickHouse.globally_enabled_for_analytics?
          ::AuditEvents::AiAuditEvents::ClickHouseFinder.new(workflow: @workflow, created_after: @created_after).execute
        else
          ::AuditEvents::AiAuditEvents::PostgresqlFinder.new(workflow: @workflow, created_after: @created_after).execute
        end
      end
      # rubocop:enable CodeReuse/Finder
    end
  end
end
