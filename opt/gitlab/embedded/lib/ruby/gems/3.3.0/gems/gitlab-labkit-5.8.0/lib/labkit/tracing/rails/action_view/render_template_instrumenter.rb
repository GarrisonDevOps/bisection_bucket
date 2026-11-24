# frozen_string_literal: true

module Labkit
  module Tracing
    module Rails
      module ActionView
        # For more information on the payloads: https://guides.rubyonrails.org/active_support_instrumentation.html
        class RenderTemplateInstrumenter < Labkit::Tracing::AbstractInstrumenter
          def span_name(payload)
            identifier = ActionView.template_identifier(payload)
            if identifier.nil?
              "render_template"
            else
              "render_template:#{identifier}"
            end
          end

          def tags(payload)
            tags = { "component" => COMPONENT_TAG }
            # OpenTelemetry rejects nil attributes, and error templates may not
            # have a layout (e.g., public/406-unsupported-browser.html).
            tags["template.id"] = payload[:identifier] if payload[:identifier]
            tags["template.layout"] = payload[:layout] if payload[:layout]
            tags
          end
        end
      end
    end
  end
end
