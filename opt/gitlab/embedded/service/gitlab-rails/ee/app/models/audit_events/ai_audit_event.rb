# frozen_string_literal: true

module AuditEvents
  class AiAuditEvent < ApplicationRecord
    include PartitionedTable
    include BulkInsertSafe
    include ::Gitlab::Utils::StrongMemoize

    CLICKHOUSE_TABLE_NAME = 'ai_audit_events'

    ALLOWED_EVENT_NAMES = %w[
      ai_agent_session_started
      ai_agent_session_ended
      ai_llm_input_sent
      ai_llm_response_received
      ai_llm_request_failed
      ai_tool_invoked
      ai_tool_response_received
      ai_tool_execution_failed
      ai_tool_execution_retried
      ai_web_search_invoked
      ai_web_fetch_invoked
      ai_user_input_received
      ai_user_output_displayed
      ai_claude_agent_session_started
      ai_claude_user_input_received
      ai_claude_response_received
      ai_claude_tool_invoked
      ai_claude_tool_response_received
      ai_claude_tool_execution_failed
      ai_claude_content_unavailable
    ].freeze

    # Attributes carried in the streamed payload and used to rebuild an
    # in-memory event in the streaming worker. Decoupled from `column_names`
    # so the contract survives a future PG to ClickHouse-only migration.
    # `id` is intentionally excluded: the streamed top-level `id` is
    # `cloud_event_id` (see `#as_json`), and the AR `id` (PG bigserial) is
    # not a stable cross-storage identifier.
    STREAMABLE_ATTRIBUTES = %w[
      cloud_event_id
      created_at
      author_id
      project_id
      namespace_id
      event_name
      ip_address
      workflow_id
      ai_governance_session_id
      details
    ].freeze

    # Mirrors the ClickHouse column DEFAULT's fallback (see
    # db/click_house/schema_cache/main/ai_audit_events.yml) for when neither
    # id resolves to a dictionary entry.
    DEFAULT_TRAVERSAL_PATH = '0/'

    self.table_name = 'ai_audit_events'
    self.primary_key = :id

    # Audit events are retained indefinitely for compliance; pruning is intentionally disabled.
    partitioned_by :created_at, strategy: :monthly, retain_for: :ever

    serialize :details, type: Hash

    attr_accessor :root_group_entity_id

    validates :cloud_event_id, presence: true
    validates :event_name, presence: true
    validates :author_id, presence: true
    # An event is keyed by a Duo workflow, an external agent session, or both while events are
    # dual-written, so this is "at least one of", not "exactly one of" as on Ai::Governance::Session.
    # Mirrored in the database by check_ai_audit_event_has_workflow_or_session.
    validates_with AnyFieldValidator, fields: %w[workflow_id ai_governance_session_id]

    scope :for_workflow, ->(workflow_id) { where(workflow_id: workflow_id) }
    # Served by idx_ai_audit_events_on_ai_governance_session_id_created_at_id with `recent_first`.
    scope :for_ai_governance_session, ->(session_id) { where(ai_governance_session_id: session_id) }
    scope :created_after, ->(time) { where(created_at: time..) }
    # Order by `created_at` first to align with the ClickHouse sort key
    # `(traversal_path, workflow_id, created_at, id)`, so the PG fallback returns
    # the same ordering as the CH-backed reader. `id` is the tiebreaker.
    # Per-workflow reads are served by the composite index
    # `idx_ai_audit_events_on_workflow_id_created_at_id`
    # on `(workflow_id, created_at DESC, id DESC)`.
    scope :recent_first, -> { order(created_at: :desc, id: :desc) }

    def self.counts_for_workflows(workflow_ids, min_created_at: nil)
      scope = where(workflow_id: workflow_ids)
      scope = scope.where(created_at: min_created_at..) if min_created_at.present?
      scope.group(:workflow_id).count
    end

    def store_to_clickhouse
      return false unless valid?

      ::ClickHouse::WriteBuffer.add(CLICKHOUSE_TABLE_NAME, to_clickhouse_csv_row)
    end

    def to_clickhouse_csv_row
      {
        id: clickhouse_id,
        event_name: event_name,
        created_at: created_at.utc.strftime('%Y-%m-%d %H:%M:%S.%6N'),
        author_id: author_id,
        project_id: project_id,
        group_id: namespace_id,
        ip_address: ip_address.to_s,
        workflow_id: workflow_id,
        ai_governance_session_id: ai_governance_session_id,
        details: (details || {}).to_json,
        traversal_path: traversal_path_value
      }
    end

    def entity
      if project_id.present?
        lazy_project
      elsif namespace_id.present?
        lazy_group
      else
        ::Gitlab::Audit::NullEntity.new
      end
    end
    strong_memoize_attr :entity

    def entity_id
      return if entity.is_a?(::Gitlab::Audit::NullEntity)

      entity.id if entity.respond_to?(:id)
    end

    def entity_type
      if project_id.present?
        'Project'
      elsif namespace_id.present?
        'Group'
      end
    end

    def target_id
      workflow_id || ai_governance_session_id
    end

    def target_type
      workflow_id ? 'Ai::DuoWorkflows::Workflow' : 'Ai::Governance::Session'
    end

    def target_details
      if workflow_id
        definition = lazy_workflow_definition.__sync || 'Unknown'
        "#{definition} session #{workflow_id}"
      else
        "External agent session #{ai_governance_session_id}"
      end
    end

    def as_json(options = {})
      super.tap do |json|
        # Use `cloud_event_id` (a stable UUID set by the producer) as the
        # streamed top-level `id` so customer-side dedup works across retries
        # and across CH-only vs PG-fallback storage. The PG bigserial `id` is
        # nil on the CH path (record never persisted) and is unique-per-row on
        # the PG path, so it is not a stable cross-storage identifier.
        json['id'] = cloud_event_id
        json['ip_address'] = ip_address.to_s
        json['entity_id'] = entity_id
        json['entity_type'] = entity_type
        json['entity_path'] = entity_path_value
        json['author_name'] = lazy_author_name
        json['target_id'] = target_id
        json['target_type'] = target_type
        json['target_details'] = target_details
        # Mirror canonical metadata into `details` so consumers of the
        # existing audit-event streaming envelope can read them via the
        # familiar nested path.
        json['details'] = canonical_details(json['details'])
      end
    end

    def root_group_entity
      return ::Group.find_by(id: root_group_entity_id) if root_group_entity_id.present?
      return if entity.is_a?(::Gitlab::Audit::NullEntity)

      group =
        case entity
        when ::Group
          entity.root_ancestor
        when ::Project
          entity.group&.root_ancestor
        end

      self.root_group_entity_id = group&.id
      group
    end
    strong_memoize_attr :root_group_entity

    def streamable_namespace
      return if entity.is_a?(::Gitlab::Audit::NullEntity)

      case entity
      when ::Project
        entity.project_namespace
      when ::Group
        entity
      end
    end
    strong_memoize_attr :streamable_namespace

    def streaming_json
      # Resolve the root group eagerly so `root_group_entity_id` is included
      # in the serialized payload. This lets the streaming worker reuse the
      # already-resolved id instead of issuing another lookup.
      root_group_entity

      ::Gitlab::Json.generate(self, methods: [:root_group_entity_id])
    end

    private

    def clickhouse_id
      cloud_event_id
    end

    def entity_path_value
      return if entity.is_a?(::Gitlab::Audit::NullEntity)

      entity&.full_path
    end

    # Must mirror the ClickHouse `traversal_path` DEFAULT's branch order exactly
    # (see db/click_house/schema_cache/main/ai_audit_events.yml), or a cold-cache
    # re-insert computes a different value and duplicates instead of collapsing.
    def traversal_path_value
      case entity
      when ::Project
        entity.project_namespace.traversal_path(with_organization: true)
      when ::Group
        entity.traversal_path(with_organization: true)
      else
        DEFAULT_TRAVERSAL_PATH
      end
    end

    def canonical_details(existing_details)
      base = existing_details.is_a?(Hash) ? existing_details.dup : {}
      base.merge(
        'event_name' => event_name,
        'author_name' => lazy_author_name,
        'author_class' => 'User',
        'target_id' => target_id,
        'target_type' => target_type,
        'target_details' => target_details,
        'ip_address' => ip_address.to_s,
        'entity_path' => entity_path_value
      )
    end

    def lazy_project
      BatchLoader.for(project_id).batch(default_value: ::Gitlab::Audit::NullEntity.new) do |ids, loader|
        ::Project.id_in(ids).preload(:project_namespace).find_each { |record| loader.call(record.id, record) }
      end
    end

    def lazy_group
      BatchLoader.for(namespace_id).batch(default_value: ::Gitlab::Audit::NullEntity.new) do |ids, loader|
        ::Group.id_in(ids).find_each { |record| loader.call(record.id, record) }
      end
    end

    def lazy_author_name
      BatchLoader.for(author_id).batch do |ids, loader|
        ::User.id_in(ids).find_each { |user| loader.call(user.id, user.name) }
      end
    end

    def lazy_workflow_definition
      BatchLoader.for(workflow_id).batch do |ids, loader|
        ::Ai::DuoWorkflows::Workflow.id_in(ids).find_each do |workflow|
          loader.call(workflow.id, workflow.workflow_definition)
        end
      end
    end
  end
end
