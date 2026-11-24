# frozen_string_literal: true

# Seeds team planning tables that are empty in the upgrade stop dump, so migrations touching them
# were never exercised by db:migrate:multi-version-upgrade.
class Gitlab::Seeder::TeamPlanning # rubocop:disable Style/ClassAndModuleChildren -- seeder convention
  SEEDED_DESCRIPTION = 'Seeded description version'
  SEEDED_NOTE = 'Seeded design note'

  attr_reader :users, :issue, :merge_request, :design, :list

  # No project carries an issue, a merge request, a design and a board at once, so each parent is
  # looked up on the condition its own table needs instead of through one shared project.
  def initialize
    @users = User.order(:id).limit(2).to_a
    @issue = Issue.first
    @merge_request = MergeRequest.first
    @design = DesignManagement::Design.first
    @list = List.first
  end

  def seed!
    warn_missing_parents
    seed_description_versions
    seed_design_user_mentions
    seed_list_user_preferences
  end

  private

  # Naming the absent parents keeps a run that seeds nothing from reading like a run that worked.
  def warn_missing_parents
    missing = []
    missing << 'user' if users.empty?
    missing << 'issue or merge request' if issue.nil? && merge_request.nil?
    missing << 'design' if design.nil?
    missing << 'board list' if list.nil?
    return if missing.empty?

    warn "\nSkipping team planning seeds that need: #{missing.join(', ')}"
  end

  # The table has no unique index to key `insert_all` on, so each row is guarded on the values it
  # writes, which also leaves a developer's own versions alone. `namespace_id` comes from the
  # getter the model's own callback uses rather than a copy of its logic.
  def seed_description_versions
    rows = [issue, merge_request].compact.map { |issuable| description_version_row(issuable) }
    rows = rows.reject { |row| DescriptionVersion.exists?(row.slice(:issue_id, :merge_request_id, :description)) }
    return if rows.empty?

    DescriptionVersion.insert_all(rows)
    print '.'
  end

  # The check constraint allows exactly one issuable, and the second row leaves `description` unset
  # and carries a `deleted_at`, which is the soft-deleted state the `visible` scope filters out.
  def description_version_row(issuable)
    issue_row = issuable.is_a?(Issue)

    { issue_id: issue_row ? issuable.id : nil,
      merge_request_id: issue_row ? nil : issuable.id,
      epic_id: nil,
      description: issue_row ? SEEDED_DESCRIPTION : nil,
      deleted_at: issue_row ? nil : now,
      namespace_id: ::Gitlab::Issuable::NamespaceGetter.new(issuable).namespace_id,
      created_at: now, updated_at: now }
  end

  # The dump carries designs but no notes on them, so the note a mention needs is created here.
  # A design carries its own sharding key, so the mention row takes the namespace from it.
  def seed_design_user_mentions
    return unless design && users.any?

    note = Note.find_by(noteable: design, note: SEEDED_NOTE) ||
      Note.create!(noteable: design, project: design.project, author: users.first, note: SEEDED_NOTE)
    print '.'

    DesignUserMention.insert_all(
      [{ design_id: design.id, note_id: note.id, namespace_id: design.namespace_id,
         mentioned_users_ids: [users.first.id], mentioned_projects_ids: nil,
         mentioned_groups_ids: nil }],
      unique_by: %i[design_id note_id])
    print '.'
  end

  # `collapsed` is nullable, so where a second user exists its preference leaves it unset.
  def seed_list_user_preferences
    return unless list && users.any?

    rows = [list_preference_row(users.first, true)]
    rows << list_preference_row(users.last, nil) if users.size > 1

    ListUserPreference.insert_all(rows, unique_by: %i[user_id list_id])
    print '.'
  end

  def list_preference_row(user, collapsed)
    { user_id: user.id, list_id: list.id, collapsed: collapsed, created_at: now, updated_at: now }
  end

  def now
    @now ||= Time.current
  end
end

Gitlab::Seeder.quiet do
  puts "\nGenerating team planning data"

  Gitlab::Seeder::TeamPlanning.new.seed!
end
