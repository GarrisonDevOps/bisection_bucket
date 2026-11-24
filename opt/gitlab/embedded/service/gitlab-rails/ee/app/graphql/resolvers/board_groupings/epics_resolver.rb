# frozen_string_literal: true

module Resolvers
  module BoardGroupings
    class EpicsResolver < BaseResolver
      include ::BoardItemFilterable

      alias_method :board, :object

      argument :issue_filters, Types::Boards::BoardIssueInputType,
        required: false,
        description: 'Filters applied when selecting issues on the board.'

      argument :sort, Types::EpicSortEnum,
        required: false,
        description: 'List epics by sort order.'

      type Types::Boards::BoardEpicType, null: true

      def resolve(**args)
        return Epic.none unless board.present?
        return Epic.none unless group.present?

        context.scoped_set!(:board, board)

        issue_params = item_filters(args[:issue_filters])
        epics = Epic.id_in(board_epic_ids(issue_params))

        args[:sort] ? epics.sort_by_attribute(args[:sort]) : epics
      end

      private

      def board_epic_ids(issue_params)
        accessible_issues(issue_params).in_epics(accessible_epics).distinct_epic_ids
      end

      def accessible_issues(issue_params)
        params = issue_params.merge(all_lists: true, board_id: board.id)

        ::Boards::Issues::ListService.new(
          board.resource_parent,
          current_user,
          params
        ).execute
      end

      def accessible_epics
        EpicsFinder.new(
          context[:current_user],
          group_id: group.id,
          state: :opened,
          include_ancestor_groups: true,
          include_descendant_groups: board.group_board?
        ).execute.without_order # Not having order here increases performance, epics will be ordering on parent query anyway.
      end

      def group
        board.project_board? ? board.project.group : board.group
      end

      def empty_issue_params?(issue_params)
        return true if issue_params.nil?

        issue_params.values.all? { |v| v.nil? || v.empty? }
      end
    end
  end
end
