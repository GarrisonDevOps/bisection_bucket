# frozen_string_literal: true

module Analytics
  module KnowledgeGraph
    class AuthorizationContext
      include Gitlab::Utils::StrongMemoize

      def self.for(user)
        ::Gitlab::SafeRequestStore.fetch([:orbit_authorization_context, user&.id]) { new(user) }
      end

      def initialize(user)
        @user = user
      end

      def admin_user?
        return false unless user

        user.can_read_all_resources?
      end

      def anonymous_user?
        user.nil?
      end

      # `{ group_traversal_ids: [{path, access_levels}, ...] }` for the
      # Knowledge Graph service. Each path carries the user's effective role
      # set so Orbit can enforce per-entity `required_role` checks.
      def reporter_plus_traversal_ids
        return { group_traversal_ids: [] } unless user

        entries = member_groups.entries.map do |entry|
          { 'path' => format_traversal_ids(entry.org_traversal_ids), 'access_levels' => entry.access_levels }
        end

        { group_traversal_ids: entries }
      end
      strong_memoize_attr :reporter_plus_traversal_ids

      def has_enabled_namespaces?
        return true if admin_user?
        return false if anonymous_user?

        member_groups.on_root_ids.any?
      end
      strong_memoize_attr :has_enabled_namespaces?

      def traversal_paths_in_scope(traversal_paths)
        return traversal_paths if admin_user?

        scopes = reporter_plus_traversal_ids[:group_traversal_ids]
        traversal_paths.select { |path| scopes.any? { |scope| path.start_with?(scope['path']) } }
      end

      # Administrators can read every namespace, so for them only the root's own enabled state counts.
      def enabled_root_namespace?(root_namespace_id)
        return member_groups.on_root_ids.include?(root_namespace_id) unless admin_user?

        enabled_ids = EnabledNamespace.root_namespace_ids_for([root_namespace_id], limit: 1)
        ::Analytics::Orbit::Billing.reject_gated_root_ids_without_access(enabled_ids).any?
      end

      attr_reader :user

      private

      def member_groups
        ::Analytics::Orbit::MemberGroups.for(user)
      end

      # Uses slash separator for ClickHouse startsWith prefix matching.
      # Search uses dash separator (see authorization_utils.rb).
      def format_traversal_ids(traversal_ids)
        "#{traversal_ids.join('/')}/"
      end
    end
  end
end
