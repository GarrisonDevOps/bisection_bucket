# frozen_string_literal: true

# Seeds the wiki page mention table, which is empty in the upgrade stop dump, so migrations
# touching it were never exercised by db:migrate:multi-version-upgrade.
#
# Exactly one of a wiki page's project and namespace is set, and the mention takes its namespace
# from the project, so only a project wiki can anchor it.
class Gitlab::Seeder::WikiPageMentions # rubocop:disable Style/ClassAndModuleChildren -- seeder convention
  SEEDED_NOTE = 'Seeded wiki page note'
  SEEDED_TITLE = 'Seeded wiki page'
  SEEDED_SLUG = 'seeded-wiki-page'

  def seed!
    meta = wiki_page_meta
    user = ::Gitlab::DatabaseImporters::AdminOrganizationImporter.seeded_admin
    return warn "\nSkipping wiki page mention seed: no wiki page or admin available" if meta.nil? || user.nil?

    note = seeded_note(meta, user)
    return if Wikis::UserMention.exists?(wiki_page_meta_id: meta.id, note_id: note.id)

    Wikis::UserMention.create!(
      wiki_page_meta: meta, note: note, namespace_id: meta.project.project_namespace_id,
      mentioned_users_ids: [user.id])
    print '.'
  end

  private

  # The dev fixtures job seeds no wiki page at all, so the metadata is created when none exists.
  def wiki_page_meta
    WikiPage::Meta.where.not(project_id: nil).order(:id).first || create_wiki_page_meta
  end

  def create_wiki_page_meta
    project = Project.order(:id).first
    return if project.nil?

    meta = WikiPage::Meta.create!(project: project, title: SEEDED_TITLE)
    # Without a canonical slug the row resolves to no page at all, while still listing like one.
    # The setter owns the canonical flag, so it writes the slug rather than the association.
    meta.canonical_slug = SEEDED_SLUG
    meta
  end

  # The dump carries wiki page metadata but no notes on it, so the note a mention needs is
  # created here rather than assumed.
  def seeded_note(meta, user)
    Note.find_by(noteable: meta, note: SEEDED_NOTE) ||
      Note.create!(noteable: meta, project: meta.project, author: user, note: SEEDED_NOTE)
  end
end

Gitlab::Seeder.quiet do
  puts "\nGenerating wiki page mention data"

  Gitlab::Seeder::WikiPageMentions.new.seed!
end
