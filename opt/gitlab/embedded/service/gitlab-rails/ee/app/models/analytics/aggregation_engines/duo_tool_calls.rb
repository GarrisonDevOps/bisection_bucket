# frozen_string_literal: true

module Analytics
  module AggregationEngines
    # Duo Chat tool call events from `ai_usage_events`, kept apart from the generic
    # AiUsageEvents engine so tool-specific fields do not apply to every event.
    class DuoToolCalls < Gitlab::Database::Aggregation::ClickHouse::Engine
      self.table_name = 'ai_usage_events'

      include Support::BaseAggregationScope

      EVENTS = Gitlab::Tracking::AiTracking.registered_events.freeze
      TOOL_CALL_EVENTS = EVENTS.values_at('tool_succeeded_duo_chat', 'tool_failed_duo_chat').freeze

      transient(:tool_name) { sql("nullIf(JSONExtractString(extras, 'tool_name'), '')") }
      transient(:session_id) { sql("nullIf(JSONExtractInt(extras, 'session_id'), 0)") }
      transient(:flow_type) { sql("nullIf(JSONExtractString(extras, 'flow_type'), '')") }
      # Names outside the registry's built-in tool catalog, such as MCP server tools, stay NULL.
      transient(:tool_access) do
        branches = Ai::ToolRules::Registry.tool_names_by_access.map do |access, names|
          "#{transient(:tool_name).call} IN (#{names.map { |name| "'#{name}'" }.join(', ')}), '#{access}'"
        end

        sql("multiIf(#{branches.join(', ')}, NULL)")
      end
      transient(:write_session_id) do
        sql("if(#{transient(:tool_access).call} = 'write', #{transient(:session_id).call}, NULL)")
      end
      # A session is read-only when every one of its calls in the scope is a known read tool.
      # The inner query groups by the sort key to dedup the ReplacingMergeTree, so the
      # window arguments are wrapped in `any` to read from those per-row groups.
      transient(:read_only_session_id) do
        session_id = transient(:session_id).call
        access = transient(:tool_access).call
        all_read = "min(any(ifNull(#{access} = 'read', 0))) OVER (PARTITION BY any(#{session_id}))"

        sql("if(#{all_read} = 1, any(#{session_id}), NULL)")
      end

      dimensions do
        column :tool_name, :string, transient(:tool_name), description: 'Name of the tool Duo Chat called'
        column :event, :string, description: 'Tool call event: `tool_succeeded_duo_chat` or `tool_failed_duo_chat`',
          formatter: ->(value) { Ai::UsageEvent.events.key(value) }
        column :tool_access, :string, transient(:tool_access),
          description: 'Whether the tool reads or writes, from the tool rules registry. ' \
            'NULL for tools outside its built-in tool catalog, such as MCP server tools.'
        column :flow_type, :string, transient(:flow_type), description: 'Duo Agent Platform flow type'
        column :user_id, :integer, description: 'User who ran the chat', association: true
        traversal_path :group_id, :integer, -> { sql('traversal_path') },
          association: {
            finder: ->(ids) { Group.id_in(ids).with_route.index_by(&:id) },
            preloader: Preloaders::GroupPolicyPreloader
          },
          description: 'Group at the requested depth of the hierarchy. ' \
            'NULL for events tracked above that depth. Events tracked in a project at that depth ' \
            'bucket by project namespace ID, which also resolves to NULL.'
        date_bucket :timestamp, :date, -> { sql('timestamp') }, description: 'Call date'
      end

      metrics do
        count description: 'Number of tool calls'
        count :users, :integer, -> { sql('user_id') }, distinct: true, description: 'Number of unique users'
        count :sessions, :integer, transient(:session_id), distinct: true,
          description: 'Number of chat sessions with at least one tool call matching the request filters. ' \
            'Chat sessions are counted whether or not they have finished.'
        count :write_sessions, :integer, transient(:write_session_id), distinct: true,
          description: 'Number of chat sessions with at least one write tool call among the calls matching ' \
            'the request filters.'
        count :read_only_sessions, :integer, transient(:read_only_session_id), distinct: true,
          description: 'Sessions whose matching tool calls are all read tools. Computed from the calls that ' \
            'match the request filters, so a `toolName`, `toolAccess` or `event` filter changes which ' \
            'sessions qualify. Sessions that called a tool outside the built-in tool catalog are not counted.'
        rate :success, numerator_if: ->(_params) { sql("event = #{EVENTS.fetch('tool_succeeded_duo_chat')}") },
          description: 'Tool calls that succeeded, divided by all tool calls. NULL when there are no calls.'
      end

      filters do
        exact_match :tool_name, :string, transient(:tool_name), description: 'Filter by one or many tool names'
        exact_not_match :tool_name, :string, transient(:tool_name),
          description: 'Exclude one or many tool names. Calls that recorded no tool name are ' \
            'excluded as well.',
          max_size: MAX_EXCLUSION_VALUES
        exact_match :event, :string, description: 'Filter by tool call event',
          formatter: ->(values) { Array.wrap(values).filter_map { |v| Ai::UsageEvent.events[v] } }
        exact_match :tool_access, :string, transient(:tool_access),
          description: 'Filter by tool access type: `read` or `write`'
        exact_not_match :tool_access, :string, transient(:tool_access),
          description: 'Exclude a tool access type. Calls to tools outside the built-in tool catalog are ' \
            'excluded as well, because their access type is NULL.',
          max_size: MAX_EXCLUSION_VALUES
        exact_match :flow_type, :string, transient(:flow_type),
          description: 'Filter by one or many Duo Agent Platform flow types'
        exact_not_match :flow_type, :string, transient(:flow_type),
          description: 'Exclude one or many Duo Agent Platform flow types. Calls that recorded no flow ' \
            'type are excluded as well.',
          max_size: MAX_EXCLUSION_VALUES
        exact_match :user_id, :string, description: 'Filter by one or many user Global IDs',
          formatter: gid_formatter
        exact_not_match :user_id, :string,
          description: 'Exclude one or many user Global IDs.',
          formatter: gid_formatter, max_size: MAX_EXCLUSION_VALUES
        descendants :group_id, :string, -> { sql('traversal_path') }, max_size: 100,
          description: 'Filter by one or many group Global IDs, including events from their descendants'
        range :timestamp, :datetime, description: 'Filter by call timestamp'
      end

      def self.prepare_base_aggregation_scope(objects)
        builder = ClickHouse::Client::QueryBuilder.new(table_name)

        super.where(builder[:event].in(TOOL_CALL_EVENTS))
      end
    end
  end
end
