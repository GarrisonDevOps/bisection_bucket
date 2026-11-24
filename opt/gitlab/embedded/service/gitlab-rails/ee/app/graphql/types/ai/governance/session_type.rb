# frozen_string_literal: true

module Types
  module Ai
    module Governance
      # Authorization is enforced upstream: the parent field requires `:read_agent_artifacts`,
      # and the sessions finder checks it again.
      #
      # Each object is a row hash from `siphon_ai_governance_sessions` when ClickHouse is enabled,
      # and an `Ai::Governance::Session` record otherwise.
      class SessionType < ::Types::BaseObject # rubocop:disable Graphql/AuthorizeTypes -- parent field authorizes
        graphql_name 'AiGovernanceSession'
        description 'AI session recorded for AI governance, from GitLab Duo or an external agent.'

        # Counts up to `limit` (1000 by default, like other large connections). Runs a ClickHouse COUNT when the
        # items are a QueryBuilder. On the PostgreSQL path, counts the finder's plain `count_relation` attached by
        # the resolver. Otherwise, the ActiveRecord count.
        class SessionConnectionType < ::Types::LimitedCountableConnectionType # rubocop:disable Graphql/AuthorizeTypes -- parent field authorizes
          graphql_name 'AiGovernanceSessionConnection'

          def count(limit:)
            items = object.items
            return limited_count(items.count_relation, limit) if items.respond_to?(:count_relation)
            return super unless items.is_a?(::ClickHouse::Client::QueryBuilder)

            base = items.dup.tap { |query| query.manager.ast.orders = [] }
            inner_sql = base.select(Arel.sql('1')).limit(limit + 1).to_sql
            outer = ::ClickHouse::Client::QueryBuilder.new(Arel.sql("(#{inner_sql})")).select(Arel.sql('count()'))

            # A COUNT query always returns one row.
            [::ClickHouse::Client.select(outer, :main).first.fetch('count()').to_i, limit + 1].min
          end
        end

        connection_type_class SessionConnectionType

        authorize_granular_token skip_reason: :parent_authorizes

        PROJECT_PRELOADS = [:route, { namespace: :route }].freeze

        field :id, ::Types::GlobalIDType[::Ai::Governance::Session],
          null: false,
          description: 'Global ID of the session.'

        field :session_id, GraphQL::Types::String,
          null: true,
          description: 'ID of the session in its source. For GitLab Duo sessions, the Duo workflow ID. ' \
            'For other sources, the session ID from the external agent.'

        field :flow_type, GraphQL::Types::String,
          null: true,
          hash_key: 'flow_type',
          description: 'Flow type of the session, for example `chat`. Values differ between sources.'

        field :agent_type, GraphQL::Types::String,
          null: true,
          hash_key: 'agent_type',
          description: 'Type of the agent that ran the session, for example `claude-code`. ' \
            'Values differ between sources.'

        field :source, ::Types::Ai::Governance::SessionSourceEnum,
          null: false,
          description: 'Source that recorded the session.'

        field :session_started_at, ::Types::TimeType, # rubocop:disable GraphQL/ExtractType -- scalar attributes of the session itself
          null: false,
          description: 'Timestamp of when the session started.'

        field :web_path, GraphQL::Types::String,
          null: true,
          description: 'Path of the session page. Null for sessions from sources other than GitLab Duo, ' \
            'and for GitLab Duo sessions without a project.'

        field :download_path, GraphQL::Types::String,
          null: true,
          description: 'Path to download the session artifact as a JSON file. ' \
            'Null for GitLab Duo sessions without a workflow, ' \
            'and for sessions from other sources when ClickHouse is not enabled.'

        field :project, ::Types::ProjectType,
          null: true,
          description: 'Project the session belongs to. Null for namespace-scoped sessions, ' \
            'or when the current user cannot read the project.'

        field :triggered_by, ::Types::UserType,
          null: true,
          description: 'User who initiated the session.'

        field :audit_events, ::Types::AuditEvents::AiAuditEventType.connection_type,
          null: true,
          description: 'Audit events recorded for the session. Returns no events for GitLab Duo sessions ' \
            'delivered through a private messaging integration. ' \
            'This field can only be resolved for one session in any single request.' do
          extension ::Gitlab::Graphql::Limit::FieldCallCount, limit: 1
        end

        field :audit_events_count, GraphQL::Types::Int, # rubocop:disable GraphQL/ExtractType -- count of the audit_events connection
          null: true,
          description: 'Number of audit events recorded for the session.'

        field :merge_request_links, ::Types::Ai::Governance::SessionMergeRequestLinkType.connection_type,
          null: true,
          description: 'Links to merge requests the session was started from or created. ' \
            'Empty for sessions from sources other than GitLab Duo.'

        field :note_links, ::Types::Ai::Governance::SessionNoteLinkType.connection_type,
          null: true,
          description: 'Links to notes that triggered the session or that the session created. ' \
            'Empty for sessions from sources other than GitLab Duo.'

        field :work_item_links, ::Types::Ai::Governance::SessionWorkItemLinkType.connection_type,
          null: true,
          description: 'Links to work items the session was started from or created. ' \
            'Empty for sessions from sources other than GitLab Duo.'

        def id
          ::Gitlab::GlobalId.build(model_name: ::Ai::Governance::Session.name, id: object['id'])
        end

        def session_id
          gitlab_duo? ? workflow_id&.to_s : object['external_xid']
        end

        # ClickHouse rows carry the integer value; ActiveRecord sessions already return the enum name.
        def source
          return object.source if object.is_a?(::Ai::Governance::Session)

          ::Ai::Governance::Session.sources.key(object['source'].to_i)
        end

        def session_started_at
          value = object['session_started_at']
          value.is_a?(String) ? Time.zone.parse(value) : value
        end

        def project
          return unless object['project_id']

          ::Gitlab::Graphql::Loaders::BatchModelLoader.new(::Project, object['project_id'], PROJECT_PRELOADS).find
        end

        def triggered_by
          ::Gitlab::Graphql::Loaders::BatchModelLoader.new(::User, object['user_id']).find
        end

        def web_path
          return unless gitlab_duo? && workflow_id && object['project_id']

          ::Gitlab::Graphql::Lazy.with_value(project) do |project|
            next unless project

            ::Gitlab::Routing.url_helpers.project_automate_agent_session_path(project, workflow_id)
          end
        end

        def download_path
          return if gitlab_duo? && !workflow_id
          # The download endpoint reads sessions from other sources from ClickHouse only.
          return if !gitlab_duo? && !::Gitlab::ClickHouse.globally_enabled_for_analytics?

          object['project_id'] ? project_download_path : group_download_path
        end

        def audit_events
          return audit_events_query(ai_governance_session_id: object['id']) unless gitlab_duo?
          return ::AuditEvents::AiAuditEvent.none unless workflow_id

          ::Gitlab::Graphql::Lazy.with_value(workflow) do |workflow|
            # Matches SessionArtifactType, which hides audit events of private messaging sessions.
            next ::AuditEvents::AiAuditEvent.none if workflow.nil? || workflow.private_messaging_session?

            audit_events_query(workflow: workflow)
          end
        end

        # Unlike `audit_events`, no private messaging check: SyncSessionArtifactWorker never syncs those sessions.
        def audit_events_count
          return batch_audit_events_count(:sessions, object['id']) unless gitlab_duo?
          return 0 unless workflow_id

          batch_audit_events_count(:workflows, workflow_id)
        end

        def merge_request_links
          session_links(:merge_request)
        end

        def note_links
          session_links(:note)
        end

        def work_item_links
          session_links(:work_item)
        end

        private

        def session_links(kind)
          ::Gitlab::Graphql::Loaders::Ai::Governance::SessionLinksLoader.new(kind, workflow_id).find
        end

        def gitlab_duo?
          source == 'gitlab_duo'
        end

        def workflow_id
          object['workflow_id']
        end

        def workflow
          ::Gitlab::Graphql::Loaders::BatchModelLoader.new(::Ai::DuoWorkflows::Workflow, workflow_id).find
        end

        def audit_events_query(**lookup)
          created_after = session_started_at - ::Ai::Governance::Session::AUDIT_EVENTS_CLOCK_SKEW

          audit_events_finder.new(**lookup, created_after: created_after).execute
        end

        def audit_events_finder
          if ::Gitlab::ClickHouse.globally_enabled_for_analytics?
            ::AuditEvents::AiAuditEvents::ClickHouseFinder
          else
            ::AuditEvents::AiAuditEvents::PostgresqlFinder
          end
        end

        # One count query per page and kind, bounded below by the earliest session start on the page, so a count
        # is an upper bound. It matches the list unless events predate their session by over AUDIT_EVENTS_CLOCK_SKEW.
        def batch_audit_events_count(kind, id)
          BatchLoader::GraphQL.for({ id: id.to_i, started_at: session_started_at })
            .batch(key: [:ai_governance_session_audit_events_count, kind]) do |keys, loader|
            # rubocop:disable CodeReuse/ActiveRecord -- plucks from an Array of Hashes
            ids = keys.pluck(:id)
            min_created_at = keys.pluck(:started_at).min - ::Ai::Governance::Session::AUDIT_EVENTS_CLOCK_SKEW
            # rubocop:enable CodeReuse/ActiveRecord
            finder = audit_events_finder
            counts = if kind == :workflows
                       finder.counts_for_workflows(ids, min_created_at: min_created_at)
                     else
                       finder.counts_for_sessions(ids, min_created_at: min_created_at)
                     end

            keys.each { |key| loader.call(key, counts.fetch(key[:id], 0)) }
          end
        end

        def url_helpers
          ::Gitlab::Routing.url_helpers
        end

        def project_download_path
          ::Gitlab::Graphql::Lazy.with_value(project) do |project|
            next unless project

            next url_helpers.download_project_security_agent_artifact_path(project, workflow_id) if gitlab_duo?

            url_helpers.download_session_project_security_agent_artifact_path(project, object['id'])
          end
        end

        def group_download_path
          group = ::Gitlab::Graphql::Loaders::BatchModelLoader.new(::Group, object['namespace_id'], [:route]).find

          ::Gitlab::Graphql::Lazy.with_value(group) do |group|
            next unless group

            next url_helpers.download_group_security_agent_artifact_path(group, workflow_id) if gitlab_duo?

            url_helpers.download_session_group_security_agent_artifact_path(group, object['id'])
          end
        end
      end
    end
  end
end
