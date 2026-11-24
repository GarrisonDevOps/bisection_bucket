# frozen_string_literal: true

module Gitlab
  module Instrumentation
    class TopologyService
      extend RequestStoreCounters

      CALL_COUNT = :topology_service_call_count
      CALL_DURATION = :topology_service_call_duration
      BEGIN_UPDATE_COUNT = :topology_service_begin_update_count
      BEGIN_UPDATE_DURATION = :topology_service_begin_update_duration
      BEGIN_UPDATE_CREATE_RECORDS = :topology_service_begin_update_create_records
      BEGIN_UPDATE_DESTROY_RECORDS = :topology_service_begin_update_destroy_records

      class << self
        def add_call(request:, duration:)
          return unless ::Gitlab::SafeRequestStore.active?

          increment_counter(CALL_COUNT)
          increment_counter(CALL_DURATION, duration)

          return unless request.is_a?(::Gitlab::Cells::TopologyService::Claims::V1::BeginUpdateRequest)

          increment_counter(BEGIN_UPDATE_COUNT)
          increment_counter(BEGIN_UPDATE_DURATION, duration)
          increment_counter(BEGIN_UPDATE_CREATE_RECORDS, request.create_records.size)
          increment_counter(BEGIN_UPDATE_DESTROY_RECORDS, request.destroy_records.size)
        end

        def payload
          return {} if counter_value(CALL_COUNT) == 0

          payload = {
            topology_service_calls: counter_value(CALL_COUNT),
            topology_service_duration_s: counter_duration(CALL_DURATION)
          }

          return payload if counter_value(BEGIN_UPDATE_COUNT) == 0

          payload.merge(
            topology_service_begin_update_calls: counter_value(BEGIN_UPDATE_COUNT),
            topology_service_begin_update_duration_s: counter_duration(BEGIN_UPDATE_DURATION),
            topology_service_begin_update_create_records: counter_value(BEGIN_UPDATE_CREATE_RECORDS),
            topology_service_begin_update_destroy_records: counter_value(BEGIN_UPDATE_DESTROY_RECORDS)
          )
        end
      end
    end
  end
end
