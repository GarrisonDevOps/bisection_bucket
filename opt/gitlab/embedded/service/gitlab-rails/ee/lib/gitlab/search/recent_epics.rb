# frozen_string_literal: true

module Gitlab
  module Search
    class RecentEpics < RecentItems
      extend ::Gitlab::Utils::Override

      override :search
      def search(term)
        query_items_by_ids(term, latest_ids)
      end

      private

      override :query_items_by_ids
      def query_items_by_ids(term, ids)
        return Epic.none if ids.empty?

        epics = Epic.full_search(term, matched_columns: 'title')
          .id_in_ordered(ids).limit(::Gitlab::Search::RecentItems::SEARCH_LIMIT)

        # Since EpicsFinder does not support searching globally (ie. applying
        # global permissions) the most efficient option is just to load the
        # last 5 matching recently viewed epics and then do an explicit
        # permissions check
        disallowed = epics.reject { |epic| Ability.allowed?(user, :read_epic, epic) }

        return epics if disallowed.empty?

        epics.id_not_in(id: disallowed.map(&:id))
      end

      def type
        Epic
      end
    end
  end
end
