# frozen_string_literal: true

class ProjectSetting < ApplicationRecord
  include ::Gitlab::Utils::StrongMemoize
  include CascadingProjectSettingAttribute
  include Projects::SquashOption
  include Gitlab::EncryptedAttribute
  include AfterCommitQueue
  include SafelyChangeColumnDefault
  include Cells::Claimable

  cells_claims_scope { where.not(pages_unique_domain: nil) }

  cells_claims_attribute :pages_unique_domain, type: CLAIMS_CLAIM_TYPE::CLAIM_TYPE_PAGES_UNIQUE_DOMAIN

  cells_claims_metadata subject_type: CLAIMS_SUBJECT_TYPE::PROJECT, subject_key: :project_id

  columns_changing_default :auto_duo_code_review_enabled, :duo_remote_flows_enabled

  REVIEWER_ASSIGNMENT_STRATEGIES = {
    disabled: 0,
    code_owners: 1,
    # Deprecated: no longer selectable, but the value still occurs in the
    # database. Kept mapped so those rows read back as a label rather than nil.
    dap_powered: 2
  }.freeze

  ALLOWED_TARGET_PLATFORMS = %w[ios osx tvos watchos android].freeze

  # A sanity bound on input, well inside the integer column.
  MAX_GIT_THROTTLE_OVERRIDE_VALUE = 1_000_000

  # A ceiling on what the loader will pull into each process, not a cap on how
  # many projects may have an override: a write is never refused for hitting it.
  # At ~270 bytes an entry this is a few MB per process, and exceeding it is
  # reported rather than tolerated, because past it some overrides stop applying.
  MAX_PROJECTS_WITH_GIT_THROTTLE_OVERRIDE = 10_000

  # Renames accumulate redirect routes, so the paths an override has to cover are
  # bounded separately from the projects that carry one.
  MAX_GIT_THROTTLE_OVERRIDE_REDIRECTS = 10_000

  GitThrottleOverrideCeilingError = Class.new(StandardError)

  # The throttle each overridable column backs. Owned here because it names
  # columns on this table; Gitlab::RateLimit::ProjectThrottleLimits reads it.
  GIT_THROTTLE_COLUMNS = {
    unauthenticated_git_http: :throttle_unauthenticated_git_http_requests_per_period,
    authenticated_git_http: :throttle_authenticated_git_http_requests_per_period,
    authenticated_git_lfs: :throttle_authenticated_git_lfs_requests_per_period
  }.freeze

  # Minimum role allowed to create, update, toggle, and delete feature flags.
  # `developer` (the default) preserves the historical behavior where all
  # Developers can manage feature flags. `no_one_allowed` freezes management for
  # everyone, including instance admins. This is an intentional change-control
  # guardrail, not an oversight: admins do not bypass it. Lifting the freeze is
  # gated separately via the `update_feature_flags_minimum_role_setting` ability.
  FEATURE_FLAGS_MANAGEMENT_ROLES = {
    no_one_allowed: 1,
    developer: 2,
    maintainer: 3,
    owner: 4
  }.freeze

  FEATURE_FLAGS_MANAGEMENT_ACCESS_LEVELS = {
    FEATURE_FLAGS_MANAGEMENT_ROLES[:developer] => Gitlab::Access::DEVELOPER,
    FEATURE_FLAGS_MANAGEMENT_ROLES[:maintainer] => Gitlab::Access::MAINTAINER,
    FEATURE_FLAGS_MANAGEMENT_ROLES[:owner] => Gitlab::Access::OWNER
  }.freeze

  # Roles that represent a stricter security posture. Loosening the setting away
  # from one of these requires elevated authority (see ProjectPolicy).
  PRIVILEGED_FEATURE_FLAGS_MANAGEMENT_ROLES = %w[owner no_one_allowed].freeze

  HUMANIZED_ATTRIBUTES = {
    mr_default_title_template: 'Merge request default title template'
  }.freeze

  # Every project carrying at least one Git throttle override, as
  # { path => [full_path, { throttle => limit }] }. Each path, current or a
  # redirect, maps to the project's current full_path, which keys the counter.
  # Read on the rate-limiting path via Gitlab::RateLimit::ProjectThrottleLimits,
  # which caches the result.
  #
  # Ordered because the ceiling truncates: without it, which projects keep their
  # override past the ceiling varies between queries, so two Rails processes
  # would disagree about the same project.
  def self.git_throttle_overrides_by_full_path
    # One past the ceiling, so landing exactly on it is distinguishable from
    # overflowing it. Only the latter drops anyone's override.
    rows = filter_by_non_nil_throttle_fields
      .joins(project: :route)
      .order(:project_id)
      .limit(MAX_PROJECTS_WITH_GIT_THROTTLE_OVERRIDE + 1)
      .pluck(Arel.sql('routes.path'), :project_id, *GIT_THROTTLE_COLUMNS.values)

    if rows.size > MAX_PROJECTS_WITH_GIT_THROTTLE_OVERRIDE
      rows = rows.first(MAX_PROJECTS_WITH_GIT_THROTTLE_OVERRIDE)
      track_git_throttle_override_ceiling
    end

    overrides = rows.to_h do |full_path, _project_id, *limits|
      canonical = full_path.downcase
      [canonical, [canonical, GIT_THROTTLE_COLUMNS.keys.zip(limits).to_h.compact]]
    end

    # Redirects first, so a live path always wins over a stale one pointing elsewhere.
    git_throttle_override_redirects(rows).merge(overrides)
  end

  # Git HTTP keeps serving a project's pre-rename paths, because
  # Gitlab::RepoPath.find_project follows redirects. An override keyed only by the
  # current path could therefore be shed by cloning from an old one.
  #
  # Every path resolves to the project's current path, which is what the counter is
  # keyed by. Keying each path separately would give an actor one budget per
  # redirect route the project has collected.
  def self.git_throttle_override_redirects(rows)
    entries_by_project_id = rows.to_h do |full_path, project_id, *limits|
      [project_id, [full_path.downcase, GIT_THROTTLE_COLUMNS.keys.zip(limits).to_h.compact]]
    end
    return {} if entries_by_project_id.empty?

    # One past the ceiling, as the project ceiling above is, so landing exactly on
    # it is distinguishable from overflowing it.
    redirects = RedirectRoute
      .for_source_type('Project')
      .where(source_id: entries_by_project_id.keys)
      .order(:id)
      .limit(MAX_GIT_THROTTLE_OVERRIDE_REDIRECTS + 1)
      .pluck(:path, :source_id)

    if redirects.size > MAX_GIT_THROTTLE_OVERRIDE_REDIRECTS
      redirects = redirects.first(MAX_GIT_THROTTLE_OVERRIDE_REDIRECTS)
      track_git_throttle_override_redirect_ceiling
    end

    redirects.to_h { |path, source_id| [path.downcase, entries_by_project_id[source_id]] }
  end

  # Past the ceiling some projects' overrides silently stop applying. Nothing else
  # would surface that, and it is not diagnosable from the project's own page.
  def self.track_git_throttle_override_ceiling
    ::Gitlab::ErrorTracking.track_exception(
      GitThrottleOverrideCeilingError.new(
        "More than #{MAX_PROJECTS_WITH_GIT_THROTTLE_OVERRIDE} projects carry a Git throttle override"
      )
    )
  end

  # Ordered by id, so past the ceiling the oldest redirects keep their coverage and
  # the rest of a project's pre-rename paths fall back to the instance-wide limit.
  def self.track_git_throttle_override_redirect_ceiling
    message = "More than #{MAX_GIT_THROTTLE_OVERRIDE_REDIRECTS} redirect routes carry a Git throttle override"

    ::Gitlab::ErrorTracking.track_exception(GitThrottleOverrideCeilingError.new(message))
  end

  def self.human_attribute_name(attribute, *options)
    HUMANIZED_ATTRIBUTES[attribute.to_sym] || super
  end

  belongs_to :project, inverse_of: :project_setting

  ignore_column :pages_multiple_versions_enabled, remove_with: '17.9', remove_after: '2025-02-20'
  ignore_column :pages_default_domain_redirect, remove_with: '17.9', remove_after: '2025-02-20'
  ignore_column :code_owner_reviewer_assignment_strategy, remove_with: '19.0', remove_after: '2026-04-22'

  scope :filter_by_non_nil_throttle_fields, -> do
    where(GIT_THROTTLE_COLUMNS.values.map { |column| arel_table[column].not_eq(nil) }.reduce(:or))
  end
  scope :for_projects, ->(projects) { where(project_id: projects) }
  scope :with_namespace, -> { joins(project: :namespace) }
  scope :with_pages_namespace_domain, -> { where(pages_unique_domain_enabled: false) }

  cascading_attr :web_based_commit_signing_enabled

  attr_encrypted :cube_api_key,
    mode: :per_attribute_iv,
    key: :db_key_base_32,
    algorithm: 'aes-256-gcm',
    encode: false,
    encode_iv: false

  attr_encrypted :product_analytics_configurator_connection_string,
    mode: :per_attribute_iv,
    key: :db_key_base_32,
    algorithm: 'aes-256-gcm',
    encode: false,
    encode_iv: false

  self.primary_key = :project_id

  # TODO: Remove once we confirm schema rollback scenarios no longer require this explicit attribute declaration.
  attribute :reviewer_assignment_strategy, :integer, default: 0, limit: 2

  enum :reviewer_assignment_strategy, REVIEWER_ASSIGNMENT_STRATEGIES,
    prefix: :reviewer_assignment

  enum :feature_flags_minimum_role, FEATURE_FLAGS_MANAGEMENT_ROLES,
    prefix: :feature_flags_minimum_role

  validates :merge_commit_template, length: { maximum: Project::MAX_COMMIT_TEMPLATE_LENGTH }
  validates :squash_commit_template, length: { maximum: Project::MAX_COMMIT_TEMPLATE_LENGTH }
  validates :mr_default_title_template, length: { maximum: Project::MAX_MR_TITLE_TEMPLATE_LENGTH }
  validate :mr_default_title_template_no_newlines
  validates :issue_branch_template, length: { maximum: Issue::MAX_BRANCH_TEMPLATE }
  validates :target_platforms, inclusion: { in: ALLOWED_TARGET_PLATFORMS }

  # nil means "no override": the project falls back to the instance-wide
  # threshold in ApplicationSetting.
  validates(
    *GIT_THROTTLE_COLUMNS.values,
    numericality: {
      only_integer: true, greater_than: 0, less_than_or_equal_to: MAX_GIT_THROTTLE_OVERRIDE_VALUE
    },
    allow_nil: true
  )
  validates :suggested_reviewers_enabled, inclusion: { in: [true, false] }
  validates :merge_request_title_regex_description, length: { maximum:
                                                              Project::MAX_MERGE_REQUEST_TITLE_REGEX_DESCRIPTION }
  validates :merge_request_title_regex, untrusted_regexp: true,
    length: { maximum: Project::MAX_MERGE_REQUEST_TITLE_REGEX }

  validates :pages_unique_domain,
    uniqueness: { if: -> { pages_unique_domain.present? } },
    presence: { if: :require_unique_domain? }

  validate :validates_mr_default_target_self

  validate :pages_unique_domain_availability, if: :pages_unique_domain_changed?

  attribute :legacy_open_source_license_available, default: -> do
    Feature.enabled?(:legacy_open_source_license_available, type: :ops)
  end

  # Checks if a given domain is already assigned to any existing project
  def self.unique_domain_exists?(domain)
    where(pages_unique_domain: domain).exists?
  end

  # Returns true when a member with `access_level` is allowed to manage feature
  # flags, given the configured minimum role. When the minimum role is
  # `no_one_allowed` this always returns false (even for admins). For all other
  # minimum roles, admins bypass the role threshold via `can_admin_all_resources?`.
  def feature_flags_management_allowed?(access_level, user)
    minimum_role = FEATURE_FLAGS_MANAGEMENT_ROLES[feature_flags_minimum_role.to_sym]

    return false if minimum_role == FEATURE_FLAGS_MANAGEMENT_ROLES[:no_one_allowed]

    required_access_level = FEATURE_FLAGS_MANAGEMENT_ACCESS_LEVELS[minimum_role]

    access_level >= required_access_level || !!user&.can_admin_all_resources?
  end

  def feature_flags_minimum_role_privileged?
    PRIVILEGED_FEATURE_FLAGS_MANAGEMENT_ROLES.include?(feature_flags_minimum_role)
  end

  def target_platforms=(val)
    super(val&.map(&:to_s)&.sort)
  end

  def show_diff_preview_in_email?
    if project.group
      super && project.group&.show_diff_preview_in_email?
    else
      !!super
    end
  end
  strong_memoize_attr :show_diff_preview_in_email?

  def runner_registration_enabled
    Gitlab::CurrentSettings.valid_runner_registrars.include?('project') && read_attribute(:runner_registration_enabled)
  end

  def emails_enabled?
    super && project.namespace.emails_enabled?
  end
  strong_memoize_attr :emails_enabled?

  def pages_primary_domain=(value)
    super(value.presence) # Call the default setter to set the value
  end

  def branch_rule
    ::Projects::AllBranchesRule.new(project)
  end

  def reviewer_auto_assignment_available?
    false
  end

  def reviewer_auto_assignment_enabled?
    reviewer_auto_assignment_available? && reviewer_assignment_code_owners?
  end

  private

  def presence_of_merge_request_title_regex_settings
    # Either both are present, or neither
    if merge_request_title_regex.present? != merge_request_title_regex_description.present?
      errors.add :merge_request_title_regex, _('and regex description must be either both set, or neither.')
      errors.add :merge_request_title_regex_description, _('and regex must be either both set, or neither.')
    end
  end

  def mr_default_title_template_no_newlines
    return if mr_default_title_template.blank?

    return unless mr_default_title_template.match?(/[\r\n]/)

    errors.add(:mr_default_title_template, _('must be a single line'))
  end

  def validates_mr_default_target_self
    if mr_default_target_self_changed? && !project.forked?
      errors.add :mr_default_target_self, _('This setting is allowed for forked projects only')
    end
  end

  def enqueue_auto_merge_workers
    run_after_commit do
      AutoMergeProcessWorker.perform_async({ 'project_id' => project.id })
    end
  end

  def require_unique_domain?
    pages_unique_domain_enabled ||
      pages_unique_domain_in_database.present?
  end

  def pages_unique_domain_availability
    host = Gitlab.config.pages&.dig('host')

    return if host.blank?
    return unless Project.where(path: "#{pages_unique_domain}.#{host}").exists?

    errors.add(:pages_unique_domain, s_('ProjectSetting|already in use'))
  end
end

ProjectSetting.prepend_mod
