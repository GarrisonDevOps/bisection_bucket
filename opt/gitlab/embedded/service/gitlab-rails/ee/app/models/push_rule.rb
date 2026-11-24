# frozen_string_literal: true

class PushRule < ApplicationRecord
  include PushRuleable
  extend Gitlab::Cache::RequestCache

  # Legacy columns from when the instance-level ("sample") push rule lived in this
  # table, scoped to an organization by organization_id. It moved to
  # organization_push_rules; the column drop is tracked in
  # https://gitlab.com/gitlab-org/gitlab/-/work_items/623433.
  ignore_columns %i[is_sample organization_id], remove_with: '19.9', remove_after: '2027-01-21'

  request_cache_key do
    [self.id]
  end

  belongs_to :project, inverse_of: :push_rule

  delegate :organization, to: :project, allow_nil: true

  validates :project_id, presence: true, uniqueness: { on: :create }

  before_save :convert_to_re2

  def available?(feature_sym, object: nil)
    (object || project)&.feature_available?(feature_sym)
  end

  def reject_unsigned_commits
    read_setting_with_global_default(:reject_unsigned_commits)
  end
  alias_method :reject_unsigned_commits?, :reject_unsigned_commits

  def reject_unsigned_commits=(value)
    write_setting_with_global_default(:reject_unsigned_commits, value)
  end

  def commit_committer_check
    read_setting_with_global_default(:commit_committer_check)
  end
  alias_method :commit_committer_check?, :commit_committer_check

  def commit_committer_check=(value)
    write_setting_with_global_default(:commit_committer_check, value)
  end

  def commit_committer_name_check
    read_setting_with_global_default(:commit_committer_name_check)
  end
  alias_method :commit_committer_name_check?, :commit_committer_name_check

  def reject_non_dco_commits
    read_setting_with_global_default(:reject_non_dco_commits)
  end
  alias_method :reject_non_dco_commits?, :reject_non_dco_commits

  def reject_non_dco_commits=(value)
    write_setting_with_global_default(:reject_non_dco_commits, value)
  end

  def regexp_uses_re2
    # Always return true to enforce RE2 usage for security
    # Database column is maintained for compatibility but ignored
    # This regexp_uses_re2 column will be deprecated and removed in the future
    # Issue: https://gitlab.com/gitlab-org/gitlab/-/issues/553148
    true
  end

  private

  def convert_to_re2
    self.regexp_uses_re2 = true
  end

  request_cache def read_setting_with_global_default(setting)
    value = read_attribute(setting)

    # A nil project-level value means "not set": fall back to the instance-level rule.
    return value unless value.nil?

    OrganizationPushRuleFinder.new(organization).execute&.public_send(setting)
  end

  def write_setting_with_global_default(setting, value)
    enabled_globally = OrganizationPushRuleFinder.new(organization).execute&.public_send(setting)
    is_disabled = !Gitlab::Utils.to_boolean(value)

    # If setting is globally disabled and user disable it at project level,
    # reset the attr so we can use the default global if required later.
    if !enabled_globally && is_disabled
      write_attribute(setting, nil)
    else
      write_attribute(setting, value)
    end
  end
end
