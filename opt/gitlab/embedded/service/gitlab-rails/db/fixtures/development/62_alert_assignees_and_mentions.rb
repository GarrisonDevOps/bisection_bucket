# frozen_string_literal: true

# Seeds the alert assignee and mention tables, which are empty in the upgrade stop dump, so
# migrations touching them were never exercised by db:migrate:multi-version-upgrade.
class Gitlab::Seeder::AlertAssigneesAndMentions # rubocop:disable Style/ClassAndModuleChildren -- seeder convention
  SEEDED_NOTE = 'Seeded alert note'

  attr_reader :alert, :user

  def initialize
    @alert = AlertManagement::Alert.order(:id).first || Project.order(:id).first&.then do |project|
      AlertManagement::Alert.create!(project: project, title: 'Seeded alert', started_at: Time.current)
    end
    @user = ::Gitlab::DatabaseImporters::AdminOrganizationImporter.seeded_admin
  end

  # Both tables hang off the same alert, so one guard on it covers them.
  def seed!
    return warn "\nSkipping alert assignee and mention seeds: no project or admin" if alert.nil? || user.nil?

    seed_assignee
    seed_mentions
  end

  private

  def seed_assignee
    return if AlertManagement::AlertAssignee.exists?(user_id: user.id, alert_id: alert.id)

    AlertManagement::AlertAssignee.create!(alert: alert, assignee: user, project_id: alert.project_id)
    print '.'
  end

  # `note_id` is nullable, and the row without one is the mention the alert's own description
  # carries, which the partial unique index covers separately.
  def seed_mentions
    mention(nil)
    mention(seeded_note)
  end

  def mention(note)
    return if AlertManagement::AlertUserMention.exists?(
      alert_management_alert_id: alert.id, note_id: note&.id)

    AlertManagement::AlertUserMention.create!(
      alert: alert, note: note, project_id: alert.project_id, mentioned_users_ids: [user.id])
    print '.'
  end

  def seeded_note
    Note.find_by(noteable: alert, note: SEEDED_NOTE) ||
      Note.create!(noteable: alert, project: alert.project, author: user, note: SEEDED_NOTE)
  end
end

Gitlab::Seeder.quiet do
  puts "\nGenerating alert assignee and mention data"

  Gitlab::Seeder::AlertAssigneesAndMentions.new.seed!
end
