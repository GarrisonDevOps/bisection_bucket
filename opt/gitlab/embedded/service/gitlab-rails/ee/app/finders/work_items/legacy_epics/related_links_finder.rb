# frozen_string_literal: true

module WorkItems
  module LegacyEpics
    class RelatedLinksFinder
      include Gitlab::Utils::StrongMemoize

      def initialize(group, current_user:, params: {})
        @group = group
        @current_user = current_user
        @params = params
      end

      def execute
        apply_filters(find_related_work_item_links).order_by_created_at_asc
      end

      private

      def find_related_work_item_links
        cte = ::Gitlab::SQL::CTE.new(:accessible_namespace_ids, accessible_groups.select(:id))

        WorkItems::RelatedWorkItemLink
          .for_work_item_type_in_namespaces(cte, epic_type)
          .preload_for_epic_link
      end

      def apply_filters(links)
        links = links.updated_before(params[:updated_before]) if params[:updated_before]
        links = links.updated_after(params[:updated_after]) if params[:updated_after]
        links = links.created_before(params[:created_before]) if params[:created_before]
        links = links.created_after(params[:created_after]) if params[:created_after]
        links
      end

      # Same permission pattern as EE::WorkItems::WorkItemsFinder#related_groups_with_access
      def accessible_groups
        groups = group.self_and_descendants

        return groups.public_to_user unless current_user
        return groups if Ability.allowed?(current_user, :read_all_resources) || group.member?(current_user)

        ::Group.id_in(
          ::Group.groups_user_can(groups, current_user, :read_work_item, same_root: true)
        )
      end
      strong_memoize_attr :accessible_groups

      def epic_type
        ::WorkItems::TypesFramework::Provider.new(group).find_by_base_type(:epic)
      end
      strong_memoize_attr :epic_type

      attr_reader :group, :current_user, :params
    end
  end
end
