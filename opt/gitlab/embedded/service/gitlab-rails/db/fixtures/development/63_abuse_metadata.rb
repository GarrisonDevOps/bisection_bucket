# frozen_string_literal: true

# Seeds abuse_metadata so migrations touching it are exercised by db:migrate:multi-version-upgrade.
# Covers a stored metric and the empty default a row has before any metric is written.
class Gitlab::Seeder::AbuseMetadata # rubocop:disable Style/ClassAndModuleChildren -- seeder convention
  def seed!
    users = User.human.order(:id).limit(2).to_a
    return warn "\nSkipping abuse metadata seeds: fewer than two human users" if users.size < 2

    AntiAbuse::UserMetadata.insert_all(
      [
        { user_id: users.first.id, metadata: { top_level_groups_created_count: 2 } },
        { user_id: users.second.id, metadata: {} }
      ],
      unique_by: :user_id
    )
  end
end

Gitlab::Seeder.quiet do
  Gitlab::Seeder::AbuseMetadata.new.seed!
end
