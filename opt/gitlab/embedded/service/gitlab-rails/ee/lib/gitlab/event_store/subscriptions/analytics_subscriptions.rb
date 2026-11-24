# frozen_string_literal: true

module Gitlab
  module EventStore
    module Subscriptions
      class AnalyticsSubscriptions < BaseSubscriptions
        def register
          store.subscribe ::Analytics::AiUsageEventsBackfillWorker, to: ::Analytics::ClickHouseForAnalyticsEnabledEvent
        end
      end
    end
  end
end
