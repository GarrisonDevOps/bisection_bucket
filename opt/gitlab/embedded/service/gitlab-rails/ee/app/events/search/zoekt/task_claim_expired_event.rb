# frozen_string_literal: true

module Search
  module Zoekt
    class TaskClaimExpiredEvent < ::Gitlab::EventStore::CloudEvent
      event_category :search_zoekt
      event_type :task_claim_expired

      class << self
        def build
          build_cloud_event(
            source: 'instance',
            subject: 'search/zoekt/tasks'
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
