# frozen_string_literal: true

module EE
  module BoardsHelper
    extend ::Gitlab::Utils::Override

    override :board_data
    def board_data
      show_feature_promotion = @project && show_promotions? &&
        !@project.feature_available?(:scoped_issue_board)

      data = {
        board_milestone_title: board.milestone&.name,
        board_milestone_id: board.milestone_id,
        board_iteration_title: board.iteration&.title,
        board_iteration_id: board.iteration_id,
        board_assignee_username: board.assignee&.username,
        board_assignee_id: board.assignee&.id,
        label_ids: board.label_ids,
        labels: board.labels.to_json(only: [:id, :title, :color, :text_color]),
        show_promotion: show_feature_promotion,
        weights: ::Issue.weight_options,
        can_create_epic: can_create_epic?
      }

      super.merge(data).merge(licensed_features).merge(group_level_features)
    end

    def licensed_features
      # These features are available at both project- and group-level
      {
        weight_feature_available: current_board_parent.feature_available?(:issue_weights).to_s,
        milestone_lists_available: current_board_parent.feature_available?(:board_milestone_lists).to_s,
        assignee_lists_available: current_board_parent.feature_available?(:board_assignee_lists).to_s,
        scoped_labels: current_board_parent.feature_available?(:scoped_labels)&.to_s,
        scoped_issue_board_feature_enabled: current_board_parent.feature_available?(:scoped_issue_board).to_s,
        status_lists_available: current_board_parent.feature_available?(:board_status_lists).to_s,
        work_item_status_available: current_board_parent.feature_available?(:work_item_status).to_s
      }
    end

    def group_level_features
      {
        iteration_lists_available: current_board_namespace.feature_available?(:board_iteration_lists).to_s,
        epic_feature_available: current_board_namespace.feature_available?(:epics).to_s,
        iteration_feature_available: current_board_namespace.feature_available?(:iterations).to_s,
        health_status_feature_available: current_board_namespace.feature_available?(:issuable_health_status).to_s,
        sub_epics_feature_available: current_board_namespace.feature_available?(:subepics).to_s,
        has_linked_items_epics_feature: current_board_namespace.licensed_feature_available?(:linked_items_epics).to_s,
        has_custom_fields_feature: current_board_namespace.licensed_feature_available?(:custom_fields).to_s
      }
    end

    def can_create_epic?
      can?(current_user, :create_epic, current_board_namespace).to_s if board.is_a?(::Boards::EpicBoard)
    end

    override :can_update?
    def can_update?
      return can?(current_user, :update_epic, board) if board.is_a?(::Boards::EpicBoard)

      super
    end

    override :can_admin_list?
    def can_admin_list?
      return can?(current_user, :admin_epic_board_list, current_board_parent) if board.is_a?(::Boards::EpicBoard)

      super
    end

    override :can_admin_board?
    def can_admin_board?
      return can?(current_user, :admin_epic_board, current_board_parent) if board.is_a?(::Boards::EpicBoard)

      super
    end

    override :board_base_url
    def board_base_url
      return group_epic_boards_url(@group) if board.is_a?(::Boards::EpicBoard)

      super
    end
  end
end
