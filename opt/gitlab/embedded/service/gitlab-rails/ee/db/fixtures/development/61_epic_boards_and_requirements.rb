# frozen_string_literal: true

# Seeds the epic board, epic mention and requirement tables, which are empty in the upgrade stop
# dump, so migrations touching them were never exercised by db:migrate:multi-version-upgrade.
class Gitlab::Seeder::EpicBoardsAndRequirements # rubocop:disable Style/ClassAndModuleChildren -- seeder convention
  SEEDED_NOTE = 'Seeded epic note'
  SEEDED_LABEL = 'Seeded epic board label'
  SEEDED_BOARD = 'Seeded epic board'
  SEEDED_EPIC = 'Seeded epic'
  REQUIREMENT_TITLE = 'Seeded requirement'

  attr_reader :user

  def initialize
    @user = ::Gitlab::DatabaseImporters::AdminOrganizationImporter.seeded_admin
  end

  # Each table hangs off a different parent, so each one is guarded on its own.
  def seed!
    warn_missing_parents
    seed_epic_board_label
    seed_epic_list_user_preference
    seed_epic_user_mentions
    seed_requirement
  end

  private

  # Naming the parents that could not be obtained, created ones included, keeps a run that seeds
  # nothing from reading like a run that worked.
  def warn_missing_parents
    missing = []
    missing << 'seeded admin' if user.nil?
    missing << 'epic board' if epic_board.nil?
    missing << 'epic list' if epic_list.nil?
    missing << 'epic' if epic.nil?
    missing << 'project with traversal ids' if requirement_project.nil?
    return if missing.empty?

    warn "\nSkipping epic board and requirement seeds that need: #{missing.join(', ')}"
  end

  def group
    @group ||= Group.order(:id).first
  end

  # `22_epics.rb` only walks `Group.not_mass_generated`, which is empty in the dev fixtures job,
  # so the board, list and epic these tables hang off are created when none exist.
  # The three lookups below memoize through `defined?` so a refused creation is not attempted
  # again in the same run.
  def epic_board
    return @epic_board if defined?(@epic_board)

    @epic_board = Boards::EpicBoard.order(:id).first || create_epic_board
  end

  def create_epic_board
    return if group.nil?

    Boards::EpicBoard.create!(group: group, name: SEEDED_BOARD)
  end

  def epic_list
    return @epic_list if defined?(@epic_list)

    @epic_list = Boards::EpicList.order(:id).first || create_epic_list
  end

  def create_epic_list
    return if epic_board.nil?

    Boards::EpicList.create!(epic_board: epic_board, group_id: epic_board.group_id,
      list_type: :backlog)
  end

  def epic
    return @epic if defined?(@epic)

    @epic = Epic.order(:id).first || create_epic
  end

  # The service is what `22_epics.rb` uses: an epic is backed by a work item, so `Epic.create!`
  # on its own fails validation.
  def create_epic
    return if group.nil? || user.nil?

    created = WorkItems::LegacyEpics::CreateService
      .new(group: group, current_user: user, params: { title: SEEDED_EPIC })
      .execute_without_rate_limiting
    created if created&.persisted?
  end

  # A board's labels can only come from its own group, and the groups that own the seeded boards
  # carry none, so one is created there. The table has no unique index, so the pair it writes is
  # what guards a re-run.
  def seed_epic_board_label
    return if epic_board.nil?

    label = Label.where(group_id: epic_board.group_id).order(:id).first ||
      create_group_label(epic_board.group)
    return if Boards::EpicBoardLabel.exists?(epic_board_id: epic_board.id, label_id: label.id)

    Boards::EpicBoardLabel.create!(epic_board: epic_board, label: label, group_id: epic_board.group_id)
    print '.'
  end

  def create_group_label(group)
    GroupLabel.create!(group: group, title: SEEDED_LABEL, color: '#428BCA')
  end

  def seed_epic_list_user_preference
    return if epic_list.nil? || user.nil? ||
      Boards::EpicListUserPreference.exists?(user_id: user.id, epic_list_id: epic_list.id)

    Boards::EpicListUserPreference.create!(
      user: user, epic_list: epic_list, group_id: epic_list.epic_board.group_id, collapsed: true)
    print '.'
  end

  # `note_id` is nullable, and the row without one is the mention the epic's own description
  # carries, which the partial unique index covers separately.
  def seed_epic_user_mentions
    return if epic.nil? || user.nil?

    mention(epic, nil)
    mention(epic, seeded_note(epic))
  end

  def mention(epic, note)
    return if EpicUserMention.exists?(epic_id: epic.id, note_id: note&.id)

    EpicUserMention.create!(
      epic: epic, note: note, group_id: epic.group_id, mentioned_users_ids: [user.id])
    print '.'
  end

  def seeded_note(epic)
    Note.find_by(noteable: epic, note: SEEDED_NOTE) ||
      Note.create!(noteable: epic, namespace: epic.group, author: user, note: SEEDED_NOTE)
  end

  # The model is a proxy for a work item of type requirement, and `only_requirement_type_issue`
  # rejects any other type, so the issue it points at is created with that type.
  def seed_requirement
    project = requirement_project
    return if project.nil? || user.nil?

    issue = Issue.find_by(project: project, title: REQUIREMENT_TITLE) || create_requirement_issue(project)
    return if issue.nil? || RequirementsManagement::Requirement.exists?(issue_id: issue.id)

    RequirementsManagement::Requirement.create!(project: project, requirement_issue: issue)
    print '.'
  end

  # Creating the issue resolves its work item type through the project's own namespace, and that
  # read falls back to a root ancestor a freshly seeded namespace has not got, so require
  # `traversal_ids` to be populated rather than taking whichever project sorts first.
  def requirement_project
    @requirement_project ||= Project.joins(:project_namespace)
      .where.not(namespaces: { traversal_ids: [] }).order(:id).first
  end

  # The provider is built without a namespace, as `WorkItem` builds it.
  def create_requirement_issue(project)
    type = ::WorkItems::TypesFramework::Provider.new.find_by_base_type(:requirement)
    return if type.nil?

    Issue.create!(project: project, author: user, title: REQUIREMENT_TITLE, work_item_type_id: type.id)
  end
end

Gitlab::Seeder.quiet do
  puts "\nGenerating epic board and requirement data"

  Gitlab::Seeder::EpicBoardsAndRequirements.new.seed!
end
