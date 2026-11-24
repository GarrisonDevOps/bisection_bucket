# frozen_string_literal: true

# rubocop:disable Gitlab/BoundedContexts, Gitlab/NamespacedClass -- Will be decided on after https://gitlab.com/groups/gitlab-org/-/epics/16894 is finalized
class GroupPushRule < ApplicationRecord
  include PushRuleable

  INHERITABLE_ATTRIBUTES = %i[
    deny_delete_tag
    member_check
    prevent_secrets
    commit_committer_check
    commit_committer_name_check
    reject_unsigned_commits
    reject_non_dco_commits
    commit_message_regex
    commit_message_negative_regex
    branch_name_regex
    author_email_regex
    file_name_regex
    max_file_size
  ].freeze

  belongs_to :group, optional: false

  delegate :organization, to: :group

  def self.build_from_predefined(group)
    predefined = group.predefined_push_rule
    return group.build_group_push_rule unless predefined

    attrs = predefined.attributes.symbolize_keys.slice(*INHERITABLE_ATTRIBUTES)
    group.build_group_push_rule(attrs)
  end

  def available?(feature_sym, **)
    group.licensed_feature_available?(feature_sym)
  end
end
# rubocop:enable Gitlab/BoundedContexts, Gitlab/NamespacedClass -- Will be decided on after https://gitlab.com/groups/gitlab-org/-/epics/16894 is finalized
