# frozen_string_literal: true

# Seeds `board_assignees`, which is empty in the upgrade stop dump. The model is EE only, so this
# sits beside the FOSS team planning fixture rather than inside it.
class Gitlab::Seeder::TeamPlanningBoards # rubocop:disable Style/ClassAndModuleChildren -- seeder convention
  attr_reader :board, :users

  def initialize
    @board = Board.where.not(project_id: nil).order(:id).first
    @users = User.order(:id).limit(2).to_a
  end

  def seed!
    return warn_missing_dependencies unless board && users.any?

    # `ensure_group_or_project` copies the owner off the board, and the check constraint allows
    # exactly one, so a project board leaves `group_id` unset.
    rows = users.map do |user|
      { board_id: board.id, assignee_id: user.id, project_id: board.project_id, group_id: nil }
    end

    BoardAssignee.insert_all(rows, unique_by: %i[board_id assignee_id])
    print '.'
  end

  private

  def warn_missing_dependencies
    warn "\nSkipping board assignee seeds: no project board or user available"
  end
end

Gitlab::Seeder.quiet do
  puts "\nGenerating board assignee data"

  Gitlab::Seeder::TeamPlanningBoards.new.seed!
end
