# frozen_string_literal: true

module Banzai
  MissingConfigurationError = Class.new(StandardError)

  # Ports for everything the rendering pipeline needs from GitLab but cannot
  # derive on its own: URL building, reference resolution, feature flags and so
  # on. The monolith wires them in `config/initializers/0_banzai.rb`.
  #
  # Each input accepts a plain value or a callable, and callables are resolved
  # on every read rather than at boot, so a caller that stubs the underlying
  # monolith state still sees the stub. The reader passes its own arguments
  # through to the callable, so a port that needs an object, such as a URL
  # builder, is declared as `def url_builder(object)` and configured as
  # `->(object) { ... }`. Reading an input that was never set raises
  # `Banzai::MissingConfigurationError` naming the input.
  class Configuration
    # The messages the filters read through `translate`, with the values each
    # one interpolates. The host defines a message for every key.
    MESSAGE_KEYS = {
      heading_anchor_label: %i[heading],
      footnote_backref_title: %i[footnote_id],
      task_table_item_label: %i[column],
      task_item_label: %i[option],
      task_item_default_label: []
    }.freeze

    attr_writer :timeout_disabled, :with_timeout, :track_exception, :translate, :instance_url, :relative_url_root

    # Whether to skip the pipeline's time budget checks entirely.
    def timeout_disabled
      resolve(:timeout_disabled, @timeout_disabled)
    end

    # Runs the block within a time budget of `seconds`, raising
    # `Timeout::Error` when the budget runs out.
    def with_timeout(seconds, &block)
      resolve(:with_timeout, @with_timeout, seconds, &block)
    end

    # Reports an exception a filter rescued, with `extra` as context.
    def track_exception(exception, **extra)
      resolve(:track_exception, @track_exception, exception, **extra)
    end

    # Returns the user-facing message for `key` in the current locale, with
    # `values` interpolated. The messages stay in the monolith, where its
    # gettext extraction finds them.
    def translate(key, **values)
      resolve(:translate, @translate, key, **values)
    end

    # The absolute URL the instance is served at, such as
    # `https://gitlab.example.com/gitlab`. Relative links resolve against it,
    # and links to its host are internal.
    def instance_url
      resolve(:instance_url, @instance_url)
    end

    # The path prefix the instance is served under, such as `/gitlab`. Blank
    # when it is served at the root.
    def relative_url_root
      resolve(:relative_url_root, @relative_url_root)
    end

    private

    def resolve(name, value, *args, **kwargs, &block)
      if value.nil?
        raise MissingConfigurationError,
          "`Banzai` input `#{name}` is not configured. Set it with " \
            "`Banzai.configure { |config| config.#{name} = ... }`."
      end

      value.respond_to?(:call) ? value.call(*args, **kwargs, &block) : value
    end
  end
end
