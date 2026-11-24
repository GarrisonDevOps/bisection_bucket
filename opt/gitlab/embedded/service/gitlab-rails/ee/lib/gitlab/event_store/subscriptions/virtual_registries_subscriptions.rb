# frozen_string_literal: true

module Gitlab
  module EventStore
    module Subscriptions
      class VirtualRegistriesSubscriptions < BaseSubscriptions
        def register
          store.subscribe ::VirtualRegistries::DestroyLocalUpstreamsWorker,
            to: ::Projects::ProjectDeletedEvent,
            if: ->(_) { ::Gitlab.config.dependency_proxy.enabled }
          store.subscribe ::VirtualRegistries::DestroyLocalUpstreamsWorker,
            to: ::Groups::GroupDeletedEvent,
            if: ->(_) { ::Gitlab.config.dependency_proxy.enabled }
        end
      end
    end
  end
end
