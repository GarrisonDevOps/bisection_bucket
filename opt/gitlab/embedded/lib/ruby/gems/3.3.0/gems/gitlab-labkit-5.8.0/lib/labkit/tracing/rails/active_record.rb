# frozen_string_literal: true

module Labkit
  module Tracing
    module Rails
      module ActiveRecord
        autoload :SqlInstrumenter, "labkit/tracing/rails/active_record/sql_instrumenter"
        autoload :Subscriber, "labkit/tracing/rails/active_record/subscriber"

        COMPONENT_TAG = "ActiveRecord"
      end
    end
  end
end
