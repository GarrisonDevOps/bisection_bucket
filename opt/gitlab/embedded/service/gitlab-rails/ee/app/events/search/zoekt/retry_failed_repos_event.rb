# frozen_string_literal: true

module Search
  module Zoekt
    class RetryFailedReposEvent < ::Gitlab::EventStore::CloudEvent
      event_category :search_zoekt
      event_type :retry_failed_repos

      class << self
        def build
          build_cloud_event(
            source: 'instance',
            subject: 'search/zoekt/repositories'
          )
        end
      end

      def data_schema
        {
          'type' => 'object',
          'properties' => {},
          'additionalProperties' => false
        }
      end
    end
  end
end
