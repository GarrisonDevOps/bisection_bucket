# frozen_string_literal: true

module Gitlab
  module EventStore
    module Subscriptions
      class GeoSubscriptions < BaseSubscriptions
        def register
          store.subscribe ::Geo::CreateRepositoryUpdatedEventWorker,
            to: ::Repositories::KeepAroundRefsCreatedEvent,
            if: ->(_) { ::Gitlab::Geo.primary? }
        end
      end
    end
  end
end
