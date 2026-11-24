# frozen_string_literal: true

class SlackIntegration < ApplicationRecord
  include FromUnion
  include Gitlab::EncryptedAttribute

  ALL_FEATURES = %i[commands notifications].freeze

  SCOPE_COMMANDS = 'commands'
  SCOPE_CHAT_WRITE = 'chat:write'
  SCOPE_CHAT_WRITE_PUBLIC = 'chat:write.public'
  SCOPE_APP_MENTIONS_READ = 'app_mentions:read'
  SCOPE_CHANNELS_HISTORY = 'channels:history'
  SCOPE_GROUPS_HISTORY = 'groups:history'
  SCOPE_SEARCH_READ_PUBLIC = 'search:read.public'
  SCOPE_REACTIONS_WRITE = 'reactions:write'
  SCOPE_IM_HISTORY = 'im:history'
  SCOPE_MPIM_HISTORY = 'mpim:history'
  SCOPE_ASSISTANT_WRITE = 'assistant:write'
  ORGANIZATION_ALIAS = 'gitlab-organization'

  # These scopes are requested when installing the app, additional scopes
  # will need reauthorization.
  # https://api.slack.com/authentication/oauth-v2#asking
  SCOPES = [SCOPE_COMMANDS, SCOPE_CHAT_WRITE, SCOPE_CHAT_WRITE_PUBLIC].freeze

  # Extended scope set required for the Duo Agent (@mention) feature.
  DUO_SCOPES = [
    SCOPE_COMMANDS,
    SCOPE_CHAT_WRITE,
    SCOPE_CHAT_WRITE_PUBLIC,
    SCOPE_APP_MENTIONS_READ,
    SCOPE_CHANNELS_HISTORY,
    SCOPE_GROUPS_HISTORY,
    SCOPE_REACTIONS_WRITE
  ].freeze

  # Scopes for the Slack Agents feature (top bar, DMs). Only requested once the
  # `slack_duo_agent_app` release flag is on, which must not happen before the
  # updated marketplace app is published, or new installs fail with invalid_scope.
  AGENT_APP_SCOPES = [SCOPE_IM_HISTORY, SCOPE_MPIM_HISTORY, SCOPE_ASSISTANT_WRITE].freeze

  MCP_USER_SCOPES = [SCOPE_CHANNELS_HISTORY, SCOPE_SEARCH_READ_PUBLIC].freeze

  TEAMS_LIMIT = 1000

  DATABASE_ATTRIBUTES = %w[
    team_id team_name user_id bot_user_id encrypted_bot_access_token encrypted_bot_access_token_iv
  ].freeze

  belongs_to :integration
  belongs_to :project, optional: true
  belongs_to :group, optional: true
  belongs_to :organization, class_name: 'Organizations::Organization', optional: true

  attr_encrypted :bot_access_token,
    mode: :per_attribute_iv,
    key: :db_key_base_32,
    algorithm: 'aes-256-gcm',
    encode: false,
    encode_iv: false

  has_many :slack_integrations_scopes,
    class_name: '::Integrations::SlackWorkspace::IntegrationApiScope'

  has_many :slack_api_scopes,
    class_name: '::Integrations::SlackWorkspace::ApiScope',
    through: :slack_integrations_scopes

  scope :preloaded_sharding_key_parents, -> { preload(:group, :project) }
  scope :with_bot, -> { where.not(bot_user_id: nil) }
  scope :by_team, ->(team_id) { where(team_id: team_id) }
  scope :by_integration, ->(integration_ids) { where(integration_id: integration_ids) }
  # Same rows as `group_id IS NULL AND project_id IS NULL` (exactly one sharding key is set), but this form
  # can use index_slack_integrations_on_organization_id.
  scope :instance_level, -> { where.not(organization_id: nil) }
  scope :instance_level_in, ->(organization) { instance_level.where(organization: organization) }
  scope :for_groups_in, ->(group) { where(group_id: group.self_and_descendant_ids) }
  scope :for_projects_in, ->(group) { where(project_id: group.all_project_ids) }

  validates :team_id, presence: true
  validates :team_name, presence: true
  validates :alias, presence: true,
    uniqueness: { scope: :team_id, message: 'This alias has already been taken' },
    length: 2..4096
  validates :user_id, presence: true
  validates :integration, presence: true
  # Bot tokens follow the format: xoxb-#####-#####-##### (around 60 characters)
  # A generous limit of 255 allows for potential future token format changes
  validates :bot_access_token, length: { maximum: 255 }, if: :bot_access_token_changed?

  after_commit :update_active_status_of_integration, on: [:create, :destroy]

  def self.organization_alias(organization_id)
    raise ArgumentError, 'organization_id must be an Integer' unless organization_id.is_a?(Integer)

    [SlackIntegration::ORGANIZATION_ALIAS, organization_id].join('-')
  end

  def self.team_ids(limit: TEAMS_LIMIT)
    distinct.order(:team_id).limit(limit).pluck(:team_id)
  end

  # { team_id => team_name } of `team_ids`, from one install of each, the first by alias.
  # A workspace can have thousands of copies, which carry the name of their source.
  def self.team_names(team_ids)
    first_install_per_team(team_ids)
      .pluck(Arel.sql('teams.team_id'), Arel.sql('installs.team_name')).to_h
  end

  # The team IDs, of `team_ids`, whose first install by alias was granted `scope_name`. Copies share the
  # scopes of their source, and checking every install would read thousands of rows for an old workspace.
  def self.sampled_team_ids_with_scope(team_ids, scope_name)
    granted = ::Integrations::SlackWorkspace::IntegrationApiScope
      .joins(:slack_api_scope)
      .where(slack_api_scopes: { name: scope_name })
      .where(Arel.sql('slack_integrations_scopes.slack_integration_id = installs.id'))

    first_install_per_team(team_ids).where(granted.arel.exists).pluck(Arel.sql('teams.team_id'))
  end

  # One row per team: `teams.team_id` and its first install by alias as `installs`, in this scope.
  # One index lookup per team, however many installs it has.
  def self.first_install_per_team(team_ids)
    team_ids = Array.wrap(team_ids)
    return none if team_ids.empty?

    first_install = where(arel_table[:team_id].eq(Arel.sql('teams.team_id')))
      .select(:id, :team_name).order(:alias, :id).limit(1)
    teams = sanitize_sql_array(['unnest(ARRAY[?]::text[]) AS teams(team_id)', team_ids])

    unscoped.from(Arel.sql("#{teams} CROSS JOIN LATERAL (#{first_install.to_sql}) AS installs"))
  end
  private_class_method :first_install_per_team

  def self.scopes_for(duo_enabled:)
    return SCOPES unless duo_enabled
    return DUO_SCOPES unless agent_app_enabled?

    DUO_SCOPES + AGENT_APP_SCOPES
  end

  def self.agent_app_enabled?
    Feature.enabled?(:slack_duo_agent_app, :instance)
  end

  def feature_available?(feature_name)
    case feature_name
    when :commands
      # The slash commands feature requires 'commands' scope.
      # All records will support this scope, as this was the original feature.
      true
    when :notifications
      scoped_to?(SCOPE_CHAT_WRITE, SCOPE_CHAT_WRITE_PUBLIC)
    when :duo
      scoped_to?(*self.class.scopes_for(duo_enabled: true))
    else
      false
    end
  end

  def upgrade_needed?
    !all_features_supported?
  end

  def all_features_supported?
    ALL_FEATURES.all? { |feature| feature_available?(feature) } # rubocop: disable Gitlab/FeatureAvailableUsage
  end

  def authorized_scope_names=(names)
    names = Array.wrap(names).flat_map { |name| name.split(',') }.map(&:strip)

    scopes = ::Integrations::SlackWorkspace::ApiScope.find_or_initialize_by_names(
      names, organization_id: organization_id_from_parent
    )
    self.slack_api_scopes = scopes
  end

  def authorized_scope_names
    slack_api_scopes.pluck(:name)
  end

  def organization_id_from_parent
    project&.organization_id || group&.organization_id || organization_id
  end

  def to_database_hash
    attributes_for_database.slice(*DATABASE_ATTRIBUTES)
  end

  private

  def update_active_status_of_integration
    integration.update(active: persisted?)
  end

  def scoped_to?(*names)
    return false if names.empty?

    names.to_set <= all_scopes
  end

  def all_scopes
    @all_scopes = authorized_scope_names.to_set
  end
end
