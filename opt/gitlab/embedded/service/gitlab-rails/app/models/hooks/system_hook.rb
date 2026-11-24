# frozen_string_literal: true

class SystemHook < WebHook
  extend ::Gitlab::Utils::Override
  include TriggerableHooks

  AVAILABLE_HOOKS = [
    :repository_update_hooks,
    :push_hooks,
    :tag_push_hooks,
    :merge_request_hooks
  ].freeze

  self.allow_legacy_sti_class = true

  has_many :web_hook_logs, foreign_key: 'web_hook_id', inverse_of: :web_hook

  def self.available_hooks
    AVAILABLE_HOOKS
  end

  triggerable_hooks available_hooks

  attribute :push_events, default: false
  attribute :repository_update_events, default: true
  attribute :merge_requests_events, default: false

  belongs_to :organization, class_name: 'Organizations::Organization'

  validates :url, system_hook_url: true, if: :default_organization?, unless: :url_variables?
  validates :organization_id, presence: true
  validate :validate_organization_hooks_limit, on: :create, unless: :default_organization?

  scope :for_organization, ->(organization) { where(organization: organization) }

  # Instance admins manage the default organization's hooks from /admin/hooks.
  # Hooks in any other organization are managed by organization admins.
  def default_organization?
    Organizations::Organization.default?(organization_id)
  end

  override :allow_local_requests?
  def allow_local_requests?
    return super unless default_organization?

    Gitlab::CurrentSettings.allow_local_requests_from_system_hooks?
  end

  def pluralized_name
    s_('Webhooks|System hooks')
  end

  def help_path
    Gitlab::Routing.url_helpers.help_page_path('administration/system_hooks.md')
  end

  override :validate_public_url?
  def validate_public_url?
    !default_organization?
  end

  # Every system hook read must filter by organization, see the isolation shared examples.
  # `ApplicationRecord` aliases `reset` to its own `reload`, so it needs aliasing again here.
  override :reload
  def reload(options = nil)
    self.class.for_organization(organization_id).scoping(all_queries: true) { super }
  end
  alias_method :reset, :reload

  # Instance-level only. SystemHook stays out of ENABLED_HOOK_TYPES, so the
  # executable/disabled scopes don't reflect this, check #executable? per hook.
  override :auto_disabling_enabled?
  def auto_disabling_enabled?
    !default_organization? && self.class.auto_disabling_feature_enabled?
  end

  override :application_context
  def application_context
    super.merge(organization: organization)
  end

  private

  def validate_organization_hooks_limit
    limits = ::GitlabSubscriptions::SystemDefined::Plan.default.actual_limits
    return unless limits.exceeded?(:organization_hooks, self.class.for_organization(organization_id))

    errors.add(:base, format(_("Maximum number of %{name} (%{count}) exceeded"),
      name: 'organization hooks', count: limits.organization_hooks))
  end
end

SystemHook.prepend_mod_with('SystemHook')
