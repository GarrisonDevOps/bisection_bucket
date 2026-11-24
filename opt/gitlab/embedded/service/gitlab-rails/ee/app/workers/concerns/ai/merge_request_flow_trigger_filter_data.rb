# frozen_string_literal: true

module Ai
  # Gives the filter rules of a merge request trigger the fields of Ai::FlowTrigger::MERGE_REQUEST_FILTER_FIELDS.
  # Include it after Ai::CloudEventsFlowTriggerWorker in each worker of an event type that allows the fields.
  module MergeRequestFlowTriggerFilterData
    private

    def filter_data_extras(_cloud_event, merge_request)
      ::Ai::FlowTriggers::MergeRequestFilterData.for(merge_request)
    end
  end
end
