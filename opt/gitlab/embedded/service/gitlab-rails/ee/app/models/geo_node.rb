# frozen_string_literal: true

class GeoNode < ApplicationRecord
  include Presentable
  include Geo::SelectiveSync
  include StripAttribute
  include Gitlab::EncryptedAttribute

  # Array of repository storages to synchronize for selective sync by shards
  serialize :selective_sync_shards, type: Array

  # rubocop:disable Cop/ActiveRecordDependent -- legacy usage
  belongs_to :oauth_application, class_name: 'Authn::OauthApplication', dependent: :destroy, autosave: true
  # rubocop:enable Cop/ActiveRecordDependent -- legacy usage

  has_many :geo_node_namespace_links
  has_many :namespaces, through: :geo_node_namespace_links
  has_many :geo_node_organization_links, class_name: 'Geo::GeoNodeOrganizationLink'
  has_many :organizations, through: :geo_node_organization_links, class_name: 'Organizations::Organization'
  has_one :status, class_name: 'GeoNodeStatus'

  validates :name, presence: true, uniqueness: { case_sensitive: false }, length: { maximum: 255 }
  # Skip outbound allowlist check - only URL parsing occurs here, no HTTP requests are made.
  # Actual Geo requests use Geo::RequestService with proper controls.
  validates :url, presence: true, addressable_url: { deny_all_requests_except_allowed: false }
  validates :internal_url, addressable_url: { deny_all_requests_except_allowed: false }, allow_blank: true, allow_nil: true

  validates :primary, uniqueness: { message: 'node already exists' }, if: :primary
  validates :enabled, if: :primary, acceptance: { message: 'Geo primary node cannot be disabled' }

  validates :access_key, presence: true
  validates :encrypted_secret_access_key, presence: true

  validates :selective_sync_type, inclusion: {
    in: SELECTIVE_SYNC_TYPES,
    allow_blank: true,
    allow_nil: true
  }

  validates :repos_max_capacity, numericality: { greater_than_or_equal_to: 0 }
  validates :files_max_capacity, numericality: { greater_than_or_equal_to: 0 }
  validates :verification_max_capacity, numericality: { greater_than_or_equal_to: 0 }
  validates :container_repositories_max_capacity, numericality: { greater_than_or_equal_to: 0 }
  validates :minimum_reverification_interval, numericality: { greater_than_or_equal_to: 1 }
  validates :blob_download_timeout,
    numericality: { greater_than_or_equal_to: 1, less_than_or_equal_to: 86400 }
  validates :checksum_mismatch_report_threshold, numericality: { greater_than_or_equal_to: 1 }
  validates :checksum_mismatch_self_heal_cooldown_minutes, numericality: { greater_than_or_equal_to: 1 }

  validate :require_current_node_to_be_primary, if: :secondary?
  validate :require_hashed_storage, on: :create

  before_validation :update_dependents_attributes
  before_validation :ensure_access_keys!
  after_commit :expire_cache!

  alias_method :repair, :save # the `update_dependents_attributes` hook will take care of it

  scope :with_url_prefix, ->(prefix) { where('url LIKE ?', "#{sanitize_sql_like(prefix.to_s)}%") }
  scope :secondary_nodes, -> { where(primary: false) }
  scope :name_in, ->(names) { where(name: names) }
  scope :ordered, -> { order(:id) }
  scope :enabled, -> { where(enabled: true) }

  # rubocop:disable Gitlab/Rails/AttrEncrypted -- cop was added later than this code
  # The cop purports to be autocorrectable, but applying it breaks CI
  attr_encrypted :secret_access_key,
    key: :db_key_base_32,
    algorithm: 'aes-256-gcm',
    mode: :per_attribute_iv,
    encode: true
  # rubocop:enable Gitlab/Rails/AttrEncrypted

  strip_attributes! :name

  class << self
    # Set in gitlab.rb as external_url
    def current_node_url
      Gitlab::SafeRequestStore.fetch('geo_node:current_node_url') do
        Gitlab.config.gitlab.url
      end
    end

    # Set in gitlab.rb as geo_node_name
    def current_node_name
      Gitlab::SafeRequestStore.fetch('geo_node:current_node_name') do
        Gitlab.config.geo.node_name
      end
    end

    def current_node
      return unless column_names.include?('name')

      node = GeoNode.find_by(name: current_node_name)
      return node if node

      sanitizer = Geo::NodeNameSanitizer.new(name: current_node_name, url: current_node_url)
      GeoNode.find_by(name: sanitizer.sanitized_name)
    end

    def primary_node
      find_by(primary: true)
    end

    def unhealthy_nodes
      status_table = GeoNodeStatus.arel_table

      query = status_table[:id].eq(nil)
        .or(status_table[:cursor_last_event_id].eq(nil))
        .or(status_table[:last_successful_status_check_at].eq(nil))
        .or(status_table[:last_successful_status_check_at].lt(1.hour.ago))

      left_join_status.where(query)
    end

    def min_cursor_last_event_id
      left_join_status.minimum(:cursor_last_event_id)
    end

    def current?(node)
      return false unless node.present?

      Geo::NodeNameSanitizer.new(name: node.name, url: node.url).match?(current_node_name)
    end

    # Tries to find a GeoNode by oauth_application_id, returning nil if none could be found.
    def find_by_oauth_application_id(oauth_application_id)
      find_by(oauth_application_id: oauth_application_id)
    end

    private

    def left_join_status
      join_statement = arel_table.join(GeoNodeStatus.arel_table, Arel::Nodes::OuterJoin)
        .on(arel_table[:id].eq(GeoNodeStatus.arel_table[:geo_node_id]))

      joins(join_statement.join_sources)
    end
  end

  # An org migration target cell shares behavior with both primary and secondary
  # Geo sites.
  #
  # An org migration target cell needs to run:
  # - all of the same replication and verification code that a secondary site
  #   runs
  # - certain Geo system checks that a secondary site runs
  #
  # An org migration target cell does not need to run:
  # - Request proxying to the primary site. All requests for the org are sent
  #   directly to the source cell.
  # - OAuth against the primary site. That only happens on a secondary site with
  #   proxying disabled.
  #
  # This feature flag is only intended for use on gitlab.com cells and will not
  # be released. Each cell has its own independent feature flag value.
  def org_migration_target?
    Feature.enabled?(:org_migration_target_cell, :instance)
  end

  # Sites which are primary = 'f' and are not org migration targets are normal
  # secondary Geo sites.
  def secondary?
    !primary && !org_migration_target?
  end

  def secondary_or_org_migration_target?
    !primary
  end

  def uses_ssh_key?
    secondary? && clone_protocol == 'ssh'
  end

  def url
    read_with_ending_slash(:url)
  end

  def url=(value)
    write_with_ending_slash(:url, value)

    @uri = nil
  end

  def internal_url
    read_with_ending_slash(:internal_url).presence || read_with_ending_slash(:url)
  end

  def internal_url=(value)
    value = add_ending_slash(value) != url ? value : nil
    write_with_ending_slash(:internal_url, value)
    @internal_uri = nil
  end

  def uri
    @uri ||= URI.parse(url) if url.present?
  end

  def internal_uri
    @internal_uri ||= URI.parse(internal_url) if internal_url.present?
  end

  def omniauth_host_url
    read_without_ending_slash(:url)
  end

  # Geo API endpoint for retrieving a replicable item
  #
  # @param [String] replicable_name
  # @param [Integer] replicable_id
  def geo_retrieve_url(replicable_name:, replicable_id:)
    geo_api_url("retrieve/#{replicable_name}/#{replicable_id}")
  end

  def status_url
    geo_api_url('status')
  end

  def checksum_mismatch_reports_url
    geo_api_url('failures')
  end

  def node_api_url(node)
    api_url("geo_nodes/#{node.id}")
  end

  def graphql_url
    geo_api_url('graphql')
  end

  def snapshot_url(repository)
    url = api_url("projects/#{repository.project.id}/snapshot")
    url += "?wiki=1" if repository.repo_type.wiki?

    url
  end

  def repository_url(repository)
    Gitlab::Utils.append_path(internal_url, "#{repository.full_path}.git")
  end

  def oauth_callback_url
    Gitlab::Routing.url_helpers.oauth_geo_callback_url(url_helper_args)
  end

  def oauth_logout_url(state)
    Gitlab::Routing.url_helpers.oauth_geo_logout_url(url_helper_args.merge(state: state))
  end

  def geo_replication_details_url
    return unless secondary_or_org_migration_target?

    replicator_class =
      ::Gitlab::Geo.replication_enabled_replicator_classes.first || ::Gitlab::Geo.verification_enabled_replicator_classes.first

    # redirect to the replicables for the first SSF data type
    Gitlab::Routing.url_helpers.site_replicables_admin_geo_node_url(
      id: id, replicable_name_plural: replicator_class.replicable_name_plural, **url_helper_args
    )
  end

  def missing_oauth_application?
    primary? ? false : !oauth_application.present?
  end

  def update_clone_url!
    update_clone_url

    # Update with update_column to prevent calling callbacks as this method will
    # be called in an initializer and we don't want other callbacks
    # to mess with uninitialized dependencies.
    return unless clone_url_prefix_changed?

    Gitlab::AppLogger.info "Geo: modified clone_url_prefix to #{clone_url_prefix}"
    update_column(:clone_url_prefix, clone_url_prefix)
  end

  def replication_slots_count
    return unless primary?

    Postgresql::ReplicationSlot.count
  end

  def replication_slots_used_count
    return unless primary?

    Postgresql::ReplicationSlot.used_slots_count
  end

  def replication_slots_max_retained_wal_bytes
    return unless primary?

    Postgresql::ReplicationSlot.max_retained_wal
  end

  def logical_replication_slots_summary
    return unless primary?

    Postgresql::ReplicationSlot.logical_slots_summary
  end

  def find_or_build_status
    status || build_status
  end

  def api_url(suffix)
    Gitlab::Utils.append_path(internal_uri.to_s, "api/#{API::API.version}/#{suffix}")
  end

  private

  def geo_api_url(suffix)
    api_url("geo/#{suffix}")
  end

  def ensure_access_keys!
    return if access_key.present? && encrypted_secret_access_key.present?

    keys = Gitlab::Geo.generate_access_keys

    self.access_key = keys[:access_key]
    self.secret_access_key = keys[:secret_access_key]
  end

  def url_helper_args
    url_helper_options(uri)
  end

  def url_helper_options(given_uri)
    { protocol: given_uri.scheme, host: given_uri.host, port: given_uri.port, script_name: given_uri.path }
  end

  def update_dependents_attributes
    if primary?
      oauth_application&.destroy
      self.oauth_application = nil

      update_clone_url
    else
      update_oauth_application!
    end
  end

  # Prevent locking yourself out
  def require_current_node_to_be_primary
    return unless name == self.class.current_node_name

    errors.add(:base, _('Current node must be the primary node or you will be locking yourself out'))
  end

  # Prevent creating a Geo Node unless Hashed Storage is enabled
  def require_hashed_storage
    return if Gitlab::CurrentSettings.hashed_storage_enabled?

    errors.add(:base, _('Hashed Storage must be enabled to use Geo'))
  end

  def update_clone_url
    self.clone_url_prefix = Gitlab.config.gitlab_shell.ssh_path_prefix
  end

  def update_oauth_application!
    return unless uri

    if oauth_application.nil?
      build_oauth_application
      oauth_application.trusted = true
      oauth_application.confidential = true
      oauth_application.organization = Organizations::Organization.first # rubocop:disable Gitlab/PreventOrganizationFirst -- Geo OAuth apps are instance-level infrastructure, not user-created
    end

    oauth_application.name = "Geo node: #{url}"
    oauth_application.redirect_uri = oauth_callback_url
  end

  def expire_cache!
    Gitlab::Geo.expire_cache!
  end

  def read_with_ending_slash(attribute)
    value = read_attribute(attribute)

    add_ending_slash(value)
  end

  def read_without_ending_slash(attribute)
    value = read_attribute(attribute)

    Geo::NodeNameSanitizer.new(name: value).name_without_slash
  end

  def write_with_ending_slash(attribute, value)
    value = add_ending_slash(value)

    write_attribute(attribute, value)
  end

  def add_ending_slash(value)
    Geo::NodeNameSanitizer.new(name: value).name_with_slash
  end
end
