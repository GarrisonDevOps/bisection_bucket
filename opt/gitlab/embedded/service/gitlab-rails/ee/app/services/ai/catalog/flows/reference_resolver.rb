# frozen_string_literal: true

module Ai
  module Catalog
    module Flows
      class ReferenceResolver
        include Gitlab::Utils::StrongMemoize

        ResolvedAgent = Struct.new(:entry, :item, :version, keyword_init: true)

        def initialize(user:, flow_project:, definition:, flow_visibility:)
          @user = user
          @flow_project = flow_project
          @definition = definition
          @flow_visibility = flow_visibility
        end

        def execute
          limit_error = reference_count_error || duplicate_items_error
          return failure(limit_error) if limit_error

          agents = include_entries.map { |entry| resolve_entry(entry) }
          agent_errors = agents.filter_map { |agent| agent_error(agent) }
          return failure(agent_errors) if agent_errors.any?

          run_payload = agents.map { |agent| agent_payload(agent) }
          return failure(payload_size_error) if payload_size_exceeded?(run_payload)

          ServiceResponse.success(payload: { agents: agents, run_payload: run_payload })
        end

        private

        attr_reader :user, :flow_project, :definition, :flow_visibility

        def include_entries
          return [] unless definition.is_a?(Hash)

          Array(definition['include']).select { |entry| entry.is_a?(Hash) }
        end
        strong_memoize_attr :include_entries

        def failure(messages)
          ServiceResponse.error(message: Array(messages))
        end

        def agent_payload(resolved)
          definition = Ai::Catalog::AgentDefinition.new(resolved.item, resolved.version)

          {
            item_id: resolved.item.id.to_s,
            version: resolved.version.version,
            name: resolved.item.name,
            description: resolved.item.description,
            prompt: definition.system_prompt,
            toolset: definition.tool_names
          }
        end

        def payload_size_exceeded?(run_payload)
          ReferenceLimits.payload_size_exceeded?(:agent, Gitlab::Json.dump(run_payload).bytesize)
        end

        def payload_size_error
          s_('AICatalog|Referenced agents exceed the maximum payload size for a run')
        end

        def reference_count_error
          count = include_entries.size
          return unless ReferenceLimits.count_exceeded?(:agent, count)

          format(
            s_('AICatalog|Flow references %{count} agents, which exceeds the limit of %{limit}'),
            count: count, limit: ReferenceLimits.limit_for(:agent)
          )
        end

        def duplicate_items_error
          duplicated = include_entries.map { |entry| entry['item_id'] }.tally.select { |_, n| n > 1 }.keys
          return if duplicated.empty?

          format(
            s_('AICatalog|Flow references the same agent more than once: %{ids}'),
            ids: duplicated.join(', ')
          )
        end

        def resolve_entry(entry)
          item = referenced_items[entry['item_id'].to_i]
          version = referenced_versions[[item&.id, entry['version']]]

          ResolvedAgent.new(entry: entry, item: item, version: version)
        end

        def referenced_items
          items = Ai::Catalog::Item.with_ids(referenced_pairs.map(&:first)).to_a
          projects = Project.id_in(items.map(&:project_id))
          Namespaces::Preloaders::ProjectRootAncestorPreloader.new(projects).execute
          projects_by_id = projects.index_by(&:id)
          items.each { |item| item.project = projects_by_id[item.project_id] }

          items.index_by(&:id)
        end
        strong_memoize_attr :referenced_items

        def referenced_versions
          Ai::Catalog::ItemVersion.for_item_version_pairs(referenced_pairs).index_by do |version|
            [version.ai_catalog_item_id, version.version]
          end
        end
        strong_memoize_attr :referenced_versions

        def referenced_pairs
          include_entries.map { |entry| [entry['item_id'].to_i, entry['version']] }
        end
        strong_memoize_attr :referenced_pairs

        def agent_error(agent)
          code = checks.refusal_code(agent.item, agent.version)
          return unless code

          ReferenceChecks.refusal_message(
            code, id: agent.entry['item_id'], version: agent.entry['version'], name: agent.item&.name
          )
        end

        def checks
          ReferenceChecks.new(user: user, flow_project: flow_project, flow_visibility: flow_visibility)
        end
        strong_memoize_attr :checks
      end
    end
  end
end
