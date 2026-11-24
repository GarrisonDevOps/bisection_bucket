# frozen_string_literal: true

module Gitlab
  module EventStore
    module Subscriptions
      class PullMirrorsSubscriptions < BaseSubscriptions
        def register
          store.subscribe ::PullMirrors::ReenableConfigurationWorker, to: ::GitlabSubscriptions::RenewedEvent
        end
      end
    end
  end
end
