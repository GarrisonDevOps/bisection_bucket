# frozen_string_literal: true

module Gitlab
  module EventStore
    module Subscriptions
      class CdSubscriptions < BaseSubscriptions
        def register
          store.subscribe ::Cd::Versions::CreateFromArtifactWorker,
            to: ::ContainerRegistry::ImagePushedEvent,
            if: ->(event) { ::Cd::Versions::CreateFromArtifactWorker.dispatch?(event) }
        end
      end
    end
  end
end
