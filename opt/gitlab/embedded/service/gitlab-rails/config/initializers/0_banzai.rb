# frozen_string_literal: true

# Adapters for the ports the `gitlab-banzai` gem declares on
# `Banzai::Configuration`.
Banzai.configure do |config|
  # Driven by the `GITLAB_DISABLE_MARKDOWN_TIMEOUT` environment variable.
  config.timeout_disabled = -> { Gitlab::RenderTimeout.banzai_timeout_disabled? }
  config.with_timeout = ->(seconds, &block) do
    Gitlab::RenderTimeout.timeout(foreground: seconds, background: seconds, &block)
  end
  config.track_exception = ->(exception, **extra) { Gitlab::ErrorTracking.track_exception(exception, **extra) }
  config.instance_url = -> { Gitlab.config.gitlab.url }
  config.relative_url_root = -> { Gitlab.config.gitlab.relative_url_root }

  # The messages are written out here, rather than in the gem, so that
  # `tooling/bin/gettext_extractor` finds them. Each one is translated when
  # it is read, in the current locale.
  messages = {
    heading_anchor_label: -> { _("Link to heading '%{heading}'") },
    footnote_backref_title: -> { _("Back to reference %{footnote_id}") },
    task_table_item_label: -> { _('Check option in column "%{column}"') },
    task_item_label: -> { _('Check option: %{option}') },
    task_item_default_label: -> { _('Check option') }
  }.freeze
  config.translate = ->(key, **values) { format(messages.fetch(key).call, **values) }
end
