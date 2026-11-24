# frozen_string_literal: true

module AuditEvents
  module AiAuditEvents
    class PostgresqlFinder
      def self.counts_for_workflows(workflow_ids, min_created_at: nil)
        return {} if workflow_ids.blank?

        ::AuditEvents::AiAuditEvent.counts_for_workflows(workflow_ids, min_created_at: min_created_at)
      end

      def self.counts_for_sessions(ai_governance_session_ids, min_created_at: nil)
        return {} if ai_governance_session_ids.blank?

        scope = ::AuditEvents::AiAuditEvent.for_ai_governance_session(ai_governance_session_ids)
        scope = scope.created_after(min_created_at) if min_created_at.present?
        scope.group(:ai_governance_session_id).count # rubocop:disable CodeReuse/ActiveRecord -- grouped count over model scopes
      end

      # Looks up events by exactly one of workflow or ai_governance_session_id.
      #
      # @param created_after [Time, nil] lower bound on created_at, used for partition pruning
      def initialize(workflow: nil, ai_governance_session_id: nil, created_after: nil)
        unless workflow.nil? ^ ai_governance_session_id.nil?
          raise ArgumentError, 'Provide exactly one of workflow or ai_governance_session_id'
        end

        @workflow = workflow
        @ai_governance_session_id = ai_governance_session_id
        @created_after = created_after
      end

      def execute
        scope = if @workflow
                  ::AuditEvents::AiAuditEvent.for_workflow(@workflow.id)
                else
                  ::AuditEvents::AiAuditEvent.for_ai_governance_session(@ai_governance_session_id)
                end

        scope = scope.created_after(@created_after) if @created_after
        scope.recent_first
      end
    end
  end
end
