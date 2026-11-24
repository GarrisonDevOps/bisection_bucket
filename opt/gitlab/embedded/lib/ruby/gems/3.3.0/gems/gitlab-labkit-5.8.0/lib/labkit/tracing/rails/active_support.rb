# frozen_string_literal: true

module Labkit
  module Tracing
    module Rails
      module ActiveSupport
        autoload :CacheDeleteInstrumenter, "labkit/tracing/rails/active_support/cache_delete_instrumenter"
        autoload :CacheFetchHitInstrumenter, "labkit/tracing/rails/active_support/cache_fetch_hit_instrumenter"
        autoload :CacheGenerateInstrumenter, "labkit/tracing/rails/active_support/cache_generate_instrumenter"
        autoload :CacheReadInstrumenter, "labkit/tracing/rails/active_support/cache_read_instrumenter"
        autoload :CacheWriteInstrumenter, "labkit/tracing/rails/active_support/cache_write_instrumenter"
        autoload :Subscriber, "labkit/tracing/rails/active_support/subscriber"

        COMPONENT_TAG = "ActiveSupport"
      end
    end
  end
end
