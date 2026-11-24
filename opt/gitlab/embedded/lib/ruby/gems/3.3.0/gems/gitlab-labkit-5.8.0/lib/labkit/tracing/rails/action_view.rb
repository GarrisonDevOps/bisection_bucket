# frozen_string_literal: true

module Labkit
  module Tracing
    module Rails
      module ActionView
        autoload :RenderCollectionInstrumenter, "labkit/tracing/rails/action_view/render_collection_instrumenter"
        autoload :RenderPartialInstrumenter, "labkit/tracing/rails/action_view/render_partial_instrumenter"
        autoload :RenderTemplateInstrumenter, "labkit/tracing/rails/action_view/render_template_instrumenter"
        autoload :Subscriber, "labkit/tracing/rails/action_view/subscriber"

        COMPONENT_TAG = "ActionView"

        # Returns identifier relative to Rails.root. Rails supports different template types and returns corresponding identifiers:
        # - Text template: the identifier is "text template"
        # - Html template: the identifier is "html template"
        # - Inline template: the identifier is "inline template"
        # - Raw template: the identifier is the file path of the template
        # Therefore, the amount of returned identifiers is static.
        def self.template_identifier(payload)
          return if !defined?(::Rails.root) || payload[:identifier].nil?

          # Rails.root returns a Pathname object, whose `to_s` methods returns an absolute path without ending "/"
          # Source: https://github.com/rails/rails/blob/v6.0.3.1/railties/lib/rails.rb#L64
          payload[:identifier].sub("#{::Rails.root}/", "")
        end
      end
    end
  end
end
