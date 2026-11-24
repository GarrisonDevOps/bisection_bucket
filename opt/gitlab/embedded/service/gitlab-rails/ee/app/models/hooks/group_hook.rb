# frozen_string_literal: true

class GroupHook < WebHook
  include CustomModelNaming
  include TriggerableHooks
  include Presentable
  include Limitable
  extend ::Gitlab::Utils::Override

  self.allow_legacy_sti_class = true

  self.limit_name = 'group_hooks'
  self.limit_scope = :group
  self.singular_route_key = :hook

  triggerable_hooks [
    :confidential_issue_hooks,
    :confidential_note_hooks,
    :deployment_hooks,
    :emoji_hooks,
    :feature_flag_hooks,
    :issue_hooks,
    :job_hooks,
    :member_hooks,
    :merge_request_hooks,
    :note_hooks,
    :pipeline_hooks,
    :project_hooks,
    :push_hooks,
    :release_hooks,
    :milestone_hooks,
    :resource_access_token_hooks,
    :subgroup_hooks,
    :tag_push_hooks,
    :wiki_page_hooks,
    :vulnerability_hooks
  ]

  has_many :web_hook_logs, foreign_key: 'web_hook_id', inverse_of: :web_hook

  belongs_to :group

  def pluralized_name
    s_('Webhooks|Group hooks')
  end

  override :application_context
  def application_context
    super.merge(namespace: group, organization: group.organization)
  end

  override :parent
  def parent
    group
  end

  def present
    super(presenter_class: ::WebHooks::Group::HookPresenter)
  end
end
