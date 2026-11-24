# frozen_string_literal: true

module Gitlab
  module EventStore
    module Subscriptions
      class AppSecSubscriptions < BaseSubscriptions
        def register
          store.subscribe ::AppSec::ContainerScanning::ScanImageWorker,
            to: ::ContainerRegistry::ImagePushedEvent,
            delay: 1.minute,
            if: ->(event) { ::AppSec::ContainerScanning::ScanImageWorker.dispatch?(event) }
        end
      end
    end
  end
end
