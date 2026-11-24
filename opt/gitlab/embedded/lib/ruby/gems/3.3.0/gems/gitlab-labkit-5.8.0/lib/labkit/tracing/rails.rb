# frozen_string_literal: true

module Labkit
  module Tracing
    # Rails provides classes for instrumenting Rails events
    module Rails
      autoload :ActionView, "labkit/tracing/rails/action_view"
      autoload :ActiveRecord, "labkit/tracing/rails/active_record"
      autoload :ActiveSupport, "labkit/tracing/rails/active_support"

      ActionViewSubscriber = ActionView::Subscriber
      ActiveRecordSubscriber = ActiveRecord::Subscriber
      ActiveSupportSubscriber = ActiveSupport::Subscriber
    end
  end
end
