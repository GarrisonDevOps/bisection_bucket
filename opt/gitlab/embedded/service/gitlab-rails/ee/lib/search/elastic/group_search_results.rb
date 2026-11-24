# frozen_string_literal: true

module Search
  module Elastic
    # Always prefer to use the full class namespace when specifying a
    # superclass inside a module, because autoloading can occur in a
    # different order between execution environments.
    class GroupSearchResults < Gitlab::Elastic::SearchResults
      extend Gitlab::Utils::Override

      attr_reader :group, :default_project_filter, :filters

      def initialize(current_user, query, group:, **opts)
        @group = group
        @default_project_filter = opts.fetch(:default_project_filter, false)
        @filters = opts.fetch(:filters, {})

        super(
          current_user,
          query,
          public_and_internal_projects: opts.fetch(:public_and_internal_projects, false),
          order_by: opts.fetch(:order_by, nil),
          sort: opts.fetch(:sort, nil),
          filters: filters
        )
      end

      override :base_options
      def base_options
        # group_ids to options for traversal_ids filtering
        super.merge(search_level: 'group', group_id: group.id, group_ids: [group.id])
      end

      override :scope_options
      def scope_options(scope)
        # User uses group_id for namespace_query
        case scope
        when :epics, :wiki_blobs
          super.merge(root_ancestor_ids: [group.root_ancestor.id])
        when :users
          super.except(:group_ids) # User uses group_id for namespace_query
        when :merge_requests
          options = super
          options[:related_ids] = related_ids_for_notes(MergeRequest.name)

          options
        else
          super
        end
      end

      override :work_item_scope_options
      def work_item_scope_options(scope: nil)
        super.merge(root_ancestor_ids: [group.root_ancestor.id])
      end

      override :allowed_to_read_users?
      def allowed_to_read_users?
        super && Ability.allowed?(current_user, :read_group_member, group)
      end
    end
  end
end
