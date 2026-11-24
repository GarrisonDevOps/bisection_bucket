# frozen_string_literal: true

# Seeds source code management tables that had neither a factory nor a fixture, so migrations
# touching them were never exercised by db:migrate:multi-version-upgrade.
#
# Uses `insert_all` so rows can carry the nulls model validations reject - a later NOT NULL
# migration needs something to trip on.
class Gitlab::Seeder::SourceCodeManagement # rubocop:disable Style/ClassAndModuleChildren -- seeder convention
  attr_reader :project, :snippets

  def initialize
    @project = Project.first
    @snippets = Snippet.where('project_id IS NOT NULL OR organization_id IS NOT NULL').order(:id).limit(2).to_a
  end

  def seed!
    return warn_missing_dependencies unless project

    seed_project_daily_statistics
    seed_snippet_user_mentions
    seed_tag_gpg_signatures
  end

  private

  def warn_missing_dependencies
    warn "\nSkipping source code management seeds: no project available"
  end

  # Two dates so the partition key varies, and a zero alongside a non-zero fetch count.
  def seed_project_daily_statistics
    rows = [
      { project_id: project.id, fetch_count: 0, date: Date.current },
      { project_id: project.id, fetch_count: 17, date: Date.current - 1 }
    ]

    ProjectDailyStatistic.insert_all(rows, unique_by: %i[project_id date])
    print '.'
  end

  # Either kind of snippet can be picked, so the row takes the project when there is one and the
  # organization otherwise. No note references a snippet in a seeded instance, so note_id stays
  # null and the partial unique index on snippet_id is what makes a re-run a no-op.
  def seed_snippet_user_mentions
    return if snippets.empty?

    rows = snippets.each_with_index.map do |snippet, index|
      {
        snippet_id: snippet.id,
        note_id: nil,
        snippet_project_id: snippet.project_id,
        snippet_organization_id: snippet.project_id ? nil : snippet.organization_id,
        mentioned_users_ids: index == 0 ? [snippet.author_id] : nil,
        mentioned_projects_ids: index == 0 ? [project.id] : nil,
        mentioned_groups_ids: nil
      }
    end

    SnippetUserMention.insert_all(rows, unique_by: :snippet_user_mentions_on_snippet_id_index)
    print '.'
  end

  # `object_name` and `gpg_key_primary_keyid` are `sha_attribute`s, so the value is packed with
  # `pack('H*')` and anything but hex is silently mangled rather than rejected.
  def seed_tag_gpg_signatures
    rows = [
      { project_id: project.id, object_name: '9a1b2c3d4e5f60718293a4b5c6d7e8f901a2b3c4',
        gpg_key_primary_keyid: '1234567890ABCDEF',
        verification_status: 0, gpg_key_user_name: 'Seeded Tagger',
        gpg_key_user_email: 'seeded-tagger@example.com', created_at: now, updated_at: now },
      { project_id: project.id, object_name: '0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c',
        gpg_key_primary_keyid: 'FEDCBA0987654321',
        verification_status: 1, gpg_key_user_name: nil,
        gpg_key_user_email: nil, created_at: now, updated_at: now }
    ]

    Repositories::Tags::GpgSignature.insert_all(rows, unique_by: %i[project_id object_name])
    print '.'
  end

  def now
    @now ||= Time.current
  end
end

Gitlab::Seeder.quiet do
  puts "\nGenerating source code management data"

  Gitlab::Seeder::SourceCodeManagement.new.seed!
end
