# frozen_string_literal: true

module Ai
  module Catalog
    # Abstract finder class for AI catalog items of a container (a project or a group).
    class BaseContainerItemsFinder
      def initialize(current_user, container, params: {})
        @current_user = current_user
        @container = container
        @params = params
      end

      def execute
        return Item.none unless authorized?

        items = init_collection
        items = by_item_type(items)
        items = by_enabled_by(items)
        items = filter_items(items)
        items = by_search(items)
        ordered(items)
      end

      private

      attr_reader :current_user, :container, :params

      def authorized?
        raise NotImplementedError
      end

      def init_collection
        raise NotImplementedError
      end

      # Returns the enabled item consumers for an enablement kind, or nil when the kind
      # is unknown or unavailable for the container.
      def enabled_consumers(_kind)
        raise NotImplementedError
      end

      # Every kind accepted by `enabled_consumers`. `:none` matches items that aren't enabled by any of them.
      def enablement_kinds
        raise NotImplementedError
      end

      # Hook for filters that only apply to one kind of container.
      def filter_items(items)
        items
      end

      # Returns items enabled by any of the given kinds, plus items not enabled at all when `:none` is given.
      def by_enabled_by(items)
        kinds = Array(params[:enabled_by]).map(&:to_sym).uniq
        return items if kinds.empty?

        if kinds.include?(:none)
          # An item is never enabled in two ways at once, so "enabled by the given kinds, or not enabled
          # at all" is the same as "not enabled by any other kind". That way each kind is queried only once.
          other_ids = enabled_item_ids(enablement_kinds - kinds)
          return other_ids ? items.id_not_in(other_ids) : items
        end

        enabled_ids = enabled_item_ids(kinds)
        enabled_ids ? items.id_in(enabled_ids) : Item.none
      end

      # Returns a subquery of the item IDs enabled by any of the given kinds, or nil when none is available.
      # A UNION lets each kind use its own index, and selecting only the item ID in each branch keeps
      # index-only scans possible.
      def enabled_item_ids(kinds)
        consumers = kinds.filter_map { |kind| enabled_consumers(kind)&.select(:ai_catalog_item_id) }
        return if consumers.empty?

        ItemConsumer.from_union(consumers, remove_duplicates: false).select(:ai_catalog_item_id)
      end

      def available_items
        base = Item.not_deleted.in_organization(container.organization)

        public_scope = base.visibility_public
        if restrict_to_group_hierarchy?
          public_scope = public_scope.within_group_hierarchy_or_foundational(root_ancestor)
        end

        return public_scope unless root_ancestor.is_a?(::Group)

        restricted_scope = base.restricted_within_group_hierarchy(container)
        public_scope.or(restricted_scope)
      end

      def restrict_to_group_hierarchy?
        root_ancestor.ai_catalog_restricted_to_group_hierarchy
      end

      def root_ancestor
        @root_ancestor ||= container.root_ancestor
      end

      def by_item_type(items)
        filtered_types = get_filtered_item_types

        return Ai::Catalog::Item.none if filtered_types.empty?
        return items if filtered_types == all_types

        items.with_item_type(filtered_types)
      end

      def by_search(items)
        return items if params[:search].blank?

        items.search(params[:search])
      end

      def ordered(items)
        unless Item::SORT_SCOPES.key?(params[:sort])
          return items.visible_to_user_with_priority_ordering(current_user, allow_restricted: true)
        end

        items.sort_by_key(params[:sort])
      end

      def get_filtered_item_types
        types = params[:item_types].presence || all_types
        types.map!(&:to_sym)

        types -= [Ai::Catalog::Item::FLOW_TYPE] unless Ability.allowed?(current_user, :read_ai_catalog_flow, container)

        unless Ability.allowed?(current_user, :read_ai_catalog_third_party_flow, container)
          types -= [Ai::Catalog::Item::THIRD_PARTY_FLOW_TYPE]
        end

        types
      end

      def all_types
        Ai::Catalog::Item.item_types.keys.map(&:to_sym)
      end
    end
  end
end
