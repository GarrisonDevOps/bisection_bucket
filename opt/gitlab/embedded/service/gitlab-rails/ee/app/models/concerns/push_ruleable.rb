# frozen_string_literal: true

# rubocop:disable Gitlab/BoundedContexts, -- Will be decided on after https://gitlab.com/groups/gitlab-org/-/epics/16894 is finalized
module PushRuleable
  extend ActiveSupport::Concern

  MatchError = Class.new(StandardError)

  # Max size: 511 characters
  SHORT_REGEX_COLUMNS = %i[
    commit_message_regex
    author_email_regex
    file_name_regex
    branch_name_regex
  ].freeze

  # Max size: 2047 characters
  LONG_REGEX_COLUMNS = %i[commit_message_negative_regex].freeze

  REGEX_COLUMNS = SHORT_REGEX_COLUMNS + LONG_REGEX_COLUMNS

  AUDIT_LOG_ALLOWLIST = {
    commit_committer_check: 'reject unverified users',
    reject_unsigned_commits: 'reject unsigned commits',
    reject_non_dco_commits: 'reject non-dco commits',
    deny_delete_tag: 'do not allow users to remove Git tags with git push',
    member_check: 'check whether the commit author is a GitLab user',
    prevent_secrets: 'prevent pushing secret files',
    branch_name_regex: 'required branch name regex',
    commit_message_regex: 'required commit message regex',
    commit_message_negative_regex: 'rejected commit message regex',
    author_email_regex: 'required author email regex',
    file_name_regex: 'prohibited file name regex',
    max_file_size: 'maximum file size (MiB)'
  }.freeze
  included do
    validates :max_file_size, numericality: {
      greater_than_or_equal_to: 0,
      less_than_or_equal_to: Gitlab::Database::MAX_INT_VALUE,
      only_integer: true
    }
    validates(*REGEX_COLUMNS, untrusted_regexp: true)
    validates(*SHORT_REGEX_COLUMNS, length: { maximum: 511 })
    validates(*LONG_REGEX_COLUMNS, length: { maximum: 2047 })
  end

  FILES_DENYLIST = YAML.load_file(Rails.root.join('ee/lib/gitlab/checks/files_denylist.yml'))

  DCO_COMMIT_REGEX = 'Signed-off-by:.+<.+@.+>'

  def available?(feature_sym, object: nil)
    raise NotImplementedError, "#{self.class.name} must implement #available? method from PushRuleable concern"
  end

  def commit_validation?
    commit_message_regex.present? ||
      commit_message_negative_regex.present? ||
      branch_name_regex.present? ||
      author_email_regex.present? ||
      reject_unsigned_commits ||
      reject_non_dco_commits ||
      commit_committer_check ||
      commit_committer_name_check ||
      member_check ||
      file_name_regex.present? ||
      prevent_secrets
  end

  def commit_signature_allowed?(commit)
    return true unless available?(:reject_unsigned_commits)
    return true unless reject_unsigned_commits

    commit.has_signature?
  end

  def committer_allowed?(committer_email, current_user)
    return true unless available?(:commit_committer_check)
    return true unless commit_committer_check
    return true if current_user.verified_email?(committer_email)

    # When current_user is a composite-identity service account,
    # the committer email belongs to the scope user rather than the service account itself.
    scope_user = composite_identity_scope_user(current_user)
    scope_user.present? && scope_user.verified_email?(committer_email)
  end

  def committer_name_allowed?(committer_name, current_user)
    return true unless available?(:commit_committer_name_check)
    return true unless commit_committer_name_check

    normalized_committer_name = normalize_name(committer_name)
    return true if normalize_name(current_user.name) == normalized_committer_name

    scope_user = composite_identity_scope_user(current_user)
    return false unless scope_user

    normalize_name(scope_user.name) == normalized_committer_name
  end

  def non_dco_commit_allowed?(message)
    return true unless available?(:reject_non_dco_commits)
    return true unless reject_non_dco_commits

    data_match?(message, DCO_COMMIT_REGEX)
  end

  def commit_message_allowed?(message)
    data_match?(message, commit_message_regex, multiline: true)
  end

  def commit_message_blocked?(message)
    message = message.to_s.chomp
    commit_message_negative_regex.present? && data_match?(message, commit_message_negative_regex, multiline: true)
  end

  def branch_name_allowed?(branch)
    data_match?(branch, branch_name_regex)
  end

  def author_email_allowed?(email)
    data_match?(email, author_email_regex)
  end

  def filename_denylisted?(file_path)
    regex_list = []
    regex_list.concat(FILES_DENYLIST) if prevent_secrets
    regex_list << file_name_regex if file_name_regex

    regex_list.find { |regex| data_match?(file_path, regex) }
  end

  private

  def composite_identity_scope_user(current_user)
    identity = ::Gitlab::Auth::Identity.fabricate(current_user)
    return unless identity&.composite? && identity.linked?

    identity.scoped_user
  end

  def normalize_name(name)
    return if name.nil?

    name.unicode_normalize(:nfc)
  rescue ArgumentError, Encoding::CompatibilityError
    name
  end

  def data_match?(data, regex, multiline: false)
    if regex.present?
      regexp = Gitlab::UntrustedRegexp.new(regex, multiline: multiline)

      regexp === data.to_s
    else
      true
    end
  rescue RegexpError => e
    raise MatchError, "Regular expression '#{regex}' is invalid: #{e.message}"
  end
end
# rubocop:enable Gitlab/BoundedContexts-- Will be decided on after https://gitlab.com/groups/gitlab-org/-/epics/16894 is finalized
