# frozen_string_literal: true

module Resolvers
  class BoardListIssuesResolver < BaseResolver
    prepend ::Issues::LookAheadPreloads
    include BoardItemFilterable

    argument :filters, Types::Boards::BoardIssueInputType,
      required: false,
      description: 'Filters applied when selecting issues in the board list.'

    type Types::IssueType, null: true

    alias_method :list, :object

    # Group boards list issues from many projects, and each issue is authorized on its own, so preload what
    # the checks read for the whole list. Namespaces too: the lookahead's project group is a separate association.
    before_connection_authorization do |nodes, current_user|
      ActiveRecord::Associations::Preloader.new(records: nodes.filter_map(&:project),
        associations: [:namespace, :organization]).call
      ::Ability.preload_for_batch_checks(current_user, nodes)
    end

    # https://gitlab.com/gitlab-org/gitlab/-/issues/235681
    def self.complexity_multiplier(args)
      0.005
    end

    def resolve_with_lookahead(**args)
      filters = item_filters(args[:filters])
      mutually_exclusive_milestone_args!(filters)

      filter_params = filters.merge(board_id: list.board.id, id: list.id)
      service = ::Boards::Issues::ListService.new(list.board.resource_parent, context[:current_user], filter_params)

      apply_lookahead(service.execute)
    end

    private

    def mutually_exclusive_milestone_args!(filters)
      if filters[:milestone_title] && filters[:milestone_wildcard_id]
        raise ::Gitlab::Graphql::Errors::ArgumentError, 'Incompatible arguments: milestoneTitle, milestoneWildcardId.'
      end
    end
  end
end
