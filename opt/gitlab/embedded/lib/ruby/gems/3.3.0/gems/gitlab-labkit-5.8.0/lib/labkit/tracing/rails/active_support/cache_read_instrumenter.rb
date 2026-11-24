# frozen_string_literal: true

module Labkit
  module Tracing
    module Rails
      module ActiveSupport
        # For more information on the payloads: https://guides.rubyonrails.org/active_support_instrumentation.html
        class CacheReadInstrumenter < Labkit::Tracing::AbstractInstrumenter
          def span_name(payload)
            "cache_read"
          end

          def tags(payload)
            {
              "component" => COMPONENT_TAG,
              "cache.key" => payload[:key],
              "cache.hit" => payload[:hit],
              "cache.super_operation" => payload[:super_operation],
            }
          end
        end
      end
    end
  end
end
