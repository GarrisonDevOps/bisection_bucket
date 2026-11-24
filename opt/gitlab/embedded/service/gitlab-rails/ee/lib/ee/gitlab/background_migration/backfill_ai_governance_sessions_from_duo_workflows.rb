# frozen_string_literal: true

module EE
  module Gitlab
    module BackgroundMigration
      module BackfillAiGovernanceSessionsFromDuoWorkflows
        extend ::ActiveSupport::Concern
        extend ::Gitlab::Utils::Override

        prepended do
          cursor :id
          operation_name :backfill_ai_governance_sessions
          feature_category :compliance_management
        end

        # Ai::DuoWorkflows::Workflow environment `external`: glab sessions, moved separately.
        EXTERNAL_ENVIRONMENT = 6
        # The only private_to_invoker? messaging adapter; the live sync skips these sessions.
        PRIVATE_MESSAGING_ADAPTER = 'slack'
        SOURCE_GITLAB_DUO = 0

        # DO NOTHING on conflict: any existing row was written by the live sync and is newer.
        INSERT_SQL = <<~SQL.freeze
          WITH batch AS MATERIALIZED (
            %{workflow_ids}
          )
          INSERT INTO ai_governance_sessions
            (workflow_id, user_id, project_id, namespace_id, status, flow_type, agent_type,
             source, session_started_at, created_at, updated_at)
          SELECT
            w.id, w.user_id, w.project_id, COALESCE(w.namespace_id, p.project_namespace_id),
            w.status, w.workflow_definition, w.agent_type,
            #{SOURCE_GITLAB_DUO}, w.created_at, NOW(), NOW()
          FROM duo_workflows_workflows w
          LEFT JOIN projects p ON p.id = w.project_id
          WHERE w.id IN (SELECT id FROM batch)
            AND w.environment IS DISTINCT FROM #{EXTERNAL_ENVIRONMENT}
            AND (w.messaging_callback_context ->> 'adapter') IS DISTINCT FROM '#{PRIVATE_MESSAGING_ADAPTER}'
          ON CONFLICT (namespace_id, workflow_id) WHERE workflow_id IS NOT NULL DO NOTHING
        SQL

        override :perform
        def perform
          each_sub_batch do |sub_batch|
            connection.execute(
              format(INSERT_SQL, workflow_ids: sub_batch.select(:id).limit(sub_batch_size).to_sql)
            )
          end
        end
      end
    end
  end
end
