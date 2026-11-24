# frozen_string_literal: true

module Analytics
  module Orbit
    class MemberGroups
      include Gitlab::Utils::StrongMemoize

      # Each entry becomes one path of the Orbit token, which has a size limit.
      MAX_ENTRIES = 500

      Entry = Data.define(:organization_id, :traversal_ids, :access_levels) do
        def org_traversal_ids
          [organization_id, *traversal_ids]
        end
      end

      def self.for(user)
        ::Gitlab::SafeRequestStore.fetch([:orbit_member_groups, user&.id]) { new(user) }
      end

      def initialize(user)
        @user = user
      end

      # Sibling compaction can differ per access level, so a path keeps every level it shows up in.
      # The cap applies once to the merged entries, so the token cannot grow by MAX_ENTRIES per level.
      def entries
        start = ::Gitlab::Metrics::System.monotonic_time

        traversal_ids_per_access_level = Hash.new { |hash, level| hash[level] = [] }
        on_rows.each do |row|
          row.fetch(:access_levels).each { |level| traversal_ids_per_access_level[level] << org_traversal_ids(row) }
        end

        access_levels_per_traversal_ids = Hash.new { |hash, ids| hash[ids] = [] }
        traversal_ids_per_access_level.each do |level, traversal_ids|
          compact(traversal_ids).each { |ids| access_levels_per_traversal_ids[ids] << level }
        end

        observe_duration(start)

        entries = access_levels_per_traversal_ids.map do |(organization_id, *traversal_ids), levels|
          Entry.new(organization_id: organization_id, traversal_ids: traversal_ids, access_levels: levels.uniq.sort)
        end

        cap(entries.sort_by { |entry| entry.org_traversal_ids.join('/') })
      end
      strong_memoize_attr :entries

      def group_ids(enabled:)
        traversal_ids = entries.map(&:org_traversal_ids)
        traversal_ids += off_rows.first(MAX_ENTRIES).map { |row| org_traversal_ids(row) } unless enabled

        ::Namespaces::Traversal::TrieNode.build(traversal_ids).to_a.map(&:last)
      end

      # authorized_groups.top_level is empty for subgroup-only members, so roots come from traversal_ids.
      def root_ids
        rows.map { |row| row[:traversal_ids].first }.uniq
      end
      strong_memoize_attr :root_ids

      def on_root_ids
        return [] if root_ids.empty?

        enabled_ids = ::Analytics::KnowledgeGraph::EnabledNamespace.root_namespace_ids_for(root_ids, limit: MAX_ENTRIES)
        Billing.reject_gated_root_ids_without_access(enabled_ids)
      end
      strong_memoize_attr :on_root_ids

      private

      attr_reader :user

      def rows
        ::Search::GroupsFinder
          .new(user: user, params: { min_access_level: ::Gitlab::Access::REPORTER })
          .execute_with_access_levels
      end
      strong_memoize_attr :rows

      def on_rows
        partitioned_rows.first
      end

      def off_rows
        partitioned_rows.last
      end

      def partitioned_rows
        on_roots = on_root_ids.to_set

        rows.partition { |row| on_roots.include?(row[:traversal_ids].first) }
      end
      strong_memoize_attr :partitioned_rows

      def org_traversal_ids(row)
        [row[:organization_id], *row[:traversal_ids]]
      end

      def compact(traversal_ids)
        return [] if traversal_ids.empty?

        compacted_ids = ::Namespaces::Traversal::TrieNode.build(traversal_ids).to_a

        metrics.observe_traversal_ids_count(compacted_ids.size)
        observe_compaction_ratio(traversal_ids.size, compacted_ids.size)

        compacted_ids
      end

      def cap(entries)
        original_count = entries.size
        return entries if original_count <= MAX_ENTRIES

        metrics.increment_threshold_exceeded
        capped_entries = entries.first(MAX_ENTRIES)
        log_threshold_exceeded(original_count, capped_entries.size)
        observe_compaction_ratio(original_count, capped_entries.size)

        capped_entries
      end

      def log_threshold_exceeded(original_count, compacted_count)
        logger.warn(
          message: 'Traversal ID count exceeds threshold',
          Labkit::Fields::GL_USER_ID => user.id,
          traversal_ids_count: original_count,
          compacted_count: compacted_count,
          threshold: MAX_ENTRIES
        )
      end

      def observe_compaction_ratio(original_count, compacted_count)
        return if original_count == 0

        metrics.observe_compaction_ratio(compacted_count.to_f / original_count)
      end

      def observe_duration(start)
        duration = ::Gitlab::Metrics::System.monotonic_time - start
        ::Gitlab::Metrics::KnowledgeGraph::Request.observe_auth_context_duration(duration)
      end

      def logger
        @logger ||= ::Gitlab::KnowledgeGraph::Logger.build
      end

      def metrics
        ::Gitlab::Metrics::KnowledgeGraph::TraversalIds
      end
    end
  end
end
