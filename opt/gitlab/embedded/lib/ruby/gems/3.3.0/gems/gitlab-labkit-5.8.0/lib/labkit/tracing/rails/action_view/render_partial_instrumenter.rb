# frozen_string_literal: true

module Labkit
  module Tracing
    module Rails
      module ActionView
        # For more information on the payloads: https://guides.rubyonrails.org/active_support_instrumentation.html
        class RenderPartialInstrumenter < Labkit::Tracing::AbstractInstrumenter
          def span_name(payload)
            identifier = ActionView.template_identifier(payload)
            if identifier.nil?
              "render_partial"
            else
              "render_partial:#{identifier}"
            end
          end

          def tags(payload)
            { "component" => COMPONENT_TAG, "template.id" => payload[:identifier] }
          end
        end
      end
    end
  end
end
