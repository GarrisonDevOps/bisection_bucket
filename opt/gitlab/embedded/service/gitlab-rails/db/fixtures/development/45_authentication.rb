# frozen_string_literal: true

# Seeds authentication tables that are empty in the upgrade stop dump, so migrations touching
# them were never exercised by db:migrate:multi-version-upgrade.
#
# Uses `insert_all` so rows can carry the nulls model validations reject - a later NOT NULL
# migration needs something to trip on.
class Gitlab::Seeder::Authentication # rubocop:disable Style/ClassAndModuleChildren -- seeder convention
  ENTITY_TYPE = 'oauth_application'
  BOT_USERNAME = 'seeded_project_token_bot'
  # Doorkeeper stores a SHA512 digest of the secret rather than the secret itself, so these
  # are digested to match the shape the application writes.
  GRANT_SECRETS = %w[seeded-access-grant-active seeded-access-grant-revoked].freeze
  DEVICE_SECRETS = %w[seeded-device-code-pending seeded-device-code-polled].freeze
  # The column stops at 1000 characters, so one note sits exactly on the limit.
  LONG_NOTE = ('Seeded admin note. ' * 53).first(1000).freeze

  attr_reader :users, :group, :application

  def initialize
    @users = User.order(:id).limit(2).to_a
    @group = Group.order(:id).first
    @application = Authn::OauthApplication.order(:id).first
  end

  def seed!
    return warn_missing_dependencies unless users.any? && group

    seed_user_follow_users
    seed_user_synced_attributes_metadata
    seed_early_access_program_tracking_events
    seed_namespace_admin_notes
    seed_namespace_ldap_settings
    seed_project_access_tokens
    seed_iam_outbox
    seed_oauth_grants
  end

  private

  def warn_missing_dependencies
    warn "\nSkipping authentication seeds: no user or group available"
  end

  def seed_user_follow_users
    return if users.size < 2

    Users::UserFollowUser.insert_all(
      [{ follower_id: users.first.id, followee_id: users.last.id }],
      unique_by: %i[follower_id followee_id])
    print '.'
  end

  # Every column but `user_id` is nullable, so the second user's row leaves all of them unset for
  # a later NOT NULL migration to trip on.
  def seed_user_synced_attributes_metadata
    rows = [synced_attributes(users.first)]
    rows << null_synced_attributes(users.last) if users.size > 1

    UserSyncedAttributesMetadata.insert_all(rows, unique_by: %i[user_id])
    print '.'
  end

  def synced_attributes(user)
    { user_id: user.id, provider: 'ldapmain', name_synced: true, email_synced: true,
      location_synced: false, organization_synced: false, job_title_synced: true }
  end

  def null_synced_attributes(user)
    { user_id: user.id, provider: nil, name_synced: nil, email_synced: nil,
      location_synced: nil, organization_synced: nil, job_title_synced: nil }
  end

  # No model for this table, and only the primary key is unique, so the conflict clause cannot
  # help and the guard is what keeps a re-run from inserting again.
  def seed_early_access_program_tracking_events
    return if tracking_events_seeded?

    connection.execute(<<~SQL.squish)
      INSERT INTO early_access_program_tracking_events
        (user_id, event_name, event_label, category, created_at, updated_at)
      VALUES
        (#{users.first.id.to_i}, 'seeded_page_view', 'seeded label', 'seeded category', NOW(), NOW()),
        (#{users.first.id.to_i}, 'seeded_feature_use', NULL, NULL, NOW(), NOW())
    SQL
    print '.'
  end

  def tracking_events_seeded?
    connection.select_value(
      "SELECT 1 FROM early_access_program_tracking_events WHERE event_name = 'seeded_page_view' LIMIT 1"
    ).present?
  end

  # Only the primary key is unique here, so the guard keeps a re-run idempotent.
  def seed_namespace_admin_notes
    return if Namespace::AdminNote.exists?(namespace_id: group.id)

    Namespace::AdminNote.insert_all([
      { namespace_id: group.id, note: LONG_NOTE, created_at: now, updated_at: now },
      { namespace_id: group.id, note: nil, created_at: now, updated_at: now }
    ])
    print '.'
  end

  def seed_namespace_ldap_settings
    Namespaces::LdapSetting.insert_all(
      [{ namespace_id: group.id, sync_status: 0, sync_error: 'Seeded LDAP sync error',
         sync_last_start_at: now, sync_last_update_at: nil, sync_last_successful_at: nil,
         created_at: now, updated_at: now }],
      unique_by: %i[namespace_id])
    print '.'
  end

  # A project access token is a personal access token owned by a project bot that is a member of
  # that project, which is the chain `ResourceAccessTokens::CreateService` builds. Pairing an
  # arbitrary token with an arbitrary project would be a combination the application never makes.
  def seed_project_access_tokens
    host = token_project
    bot = project_bot
    return unless host && bot

    token = PersonalAccessToken.find_by(user_id: bot.id) || PersonalAccessToken.create!(
      user: bot, name: 'Seeded project access token', scopes: [:api],
      organization_id: host.organization_id, expires_at: 30.days.from_now)

    connection.execute(<<~SQL.squish)
      INSERT INTO project_access_tokens (personal_access_token_id, project_id)
      VALUES (#{token.id.to_i}, #{host.id.to_i})
      ON CONFLICT DO NOTHING
    SQL
    print '.'
  end

  # Adding a member records an Event, and its callback compares the project's last activity
  # against a cutoff, so a project that has never recorded any would raise there.
  def token_project
    @token_project ||= Project.where.not(last_activity_at: nil).order(:id).first
  end

  def project_bot
    @project_bot ||= User.find_by(username: BOT_USERNAME) || create_project_bot
  end

  def create_project_bot
    host = token_project
    organization = Organizations::Organization.find_by(id: host&.organization_id)
    return unless host && organization

    bot = User.new(user_type: :project_bot, username: BOT_USERNAME,
      name: 'Seeded project token bot', email: "#{BOT_USERNAME}@noreply.example.com",
      organization_id: organization.id)
    # The build service pairs `organization_id` with an organization membership. Without it the
    # bot is not a member of the organization, and adding it to a project in an isolated
    # organization would fail the same-organization check without raising.
    bot.organization_users << Organizations::OrganizationUser.new(
      organization_id: organization.id,
      access_level: Organizations::OrganizationUser.home_organization_access_level(user_is_admin: false))
    bot.assign_personal_namespace(organization)
    bot.save!
    host.add_maintainer(bot)

    bot
  end

  # `oauth_application` is the only entity type the model allows, and `insert_all` would not
  # catch a different one. The payloads come from the model's own builders so each event type
  # carries the shape the real write path produces. Both rows are marked delivered so
  # `l0_undelivered` never returns them
  # and the replication worker, which talks to an external service, leaves them alone.
  def seed_iam_outbox
    return unless application
    return if Authn::IamOutbox.exists?(entity_type: ENTITY_TYPE, entity_id: application.id)

    rows = [
      { organization_id: application.organization_id, entity_id: application.id, entity_type: ENTITY_TYPE,
        event_type: 0, payload: application.iam_outbox_upsert_payload,
        l0_delivered_at: now, l2_delivered_at: now,
        l0_attempts: 1, l2_attempts: 1, l0_last_error: nil, l2_last_error: nil,
        created_at: now, updated_at: now },
      { organization_id: application.organization_id, entity_id: application.id, entity_type: ENTITY_TYPE,
        event_type: 1, payload: application.iam_outbox_delete_payload,
        l0_delivered_at: now, l2_delivered_at: now,
        l0_attempts: 0, l2_attempts: 0, l0_last_error: 'seeded delivery error', l2_last_error: nil,
        created_at: now, updated_at: now }
    ]

    Authn::IamOutbox.insert_all(rows)
    print '.'
  end

  # The openid request points at a grant, so the grants are inserted first and looked up by token.
  def seed_oauth_grants
    return unless application

    seed_access_grants
    seed_device_grants
    seed_openid_requests
  end

  def seed_access_grants
    rows = grant_tokens.each_with_index.map do |token, index|
      { resource_owner_id: users.first.id, application_id: application.id, token: token,
        expires_in: 7200, redirect_uri: 'https://example.com/oauth/callback',
        revoked_at: index == 1 ? now : nil, scopes: 'api',
        code_challenge: index == 0 ? 'seeded-code-challenge' : nil,
        code_challenge_method: index == 0 ? 'S256' : nil,
        organization_id: application.organization_id, created_at: now }
    end

    Doorkeeper::AccessGrant.insert_all(rows, unique_by: %i[token])
    print '.'
  end

  # `user_code` and `resource_owner_id` are mutually exclusive on this model: a grant is either
  # still pending with a user code, or authorized by an owner and the code cleared.
  def seed_device_grants
    rows = device_codes.each_with_index.map do |device_code, index|
      pending = index == 0
      { application_id: application.id, device_code: device_code,
        user_code: pending ? "seeded-user-code-#{index}" : nil, expires_in: 600, scopes: 'api',
        resource_owner_id: pending ? nil : users.first.id,
        last_polling_at: pending ? nil : now,
        organization_id: application.organization_id, created_at: now }
    end

    Doorkeeper::DeviceAuthorizationGrant::DeviceGrant.insert_all(rows, unique_by: %i[device_code])
    print '.'
  end

  def seed_openid_requests
    grant = Doorkeeper::AccessGrant.find_by(token: grant_tokens.first)
    return if grant.nil? || Doorkeeper::OpenidConnect::Request.exists?(access_grant_id: grant.id)

    Doorkeeper::OpenidConnect::Request.insert_all(
      [{ access_grant_id: grant.id, nonce: 'seeded-nonce', organization_id: grant.organization_id }])
    print '.'
  end

  def grant_tokens
    GRANT_SECRETS.map { |secret| Digest::SHA512.hexdigest(secret) }
  end

  def device_codes
    DEVICE_SECRETS.map { |secret| Digest::SHA512.hexdigest(secret) }
  end

  def connection
    ApplicationRecord.connection
  end

  def now
    @now ||= Time.current
  end
end

Gitlab::Seeder.quiet do
  puts "\nGenerating authentication data"

  Gitlab::Seeder::Authentication.new.seed!
end
