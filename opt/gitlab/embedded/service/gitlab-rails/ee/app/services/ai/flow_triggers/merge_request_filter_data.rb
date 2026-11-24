# frozen_string_literal: true

module Ai
  module FlowTriggers
    # The values of Ai::FlowTrigger::MERGE_REQUEST_FILTER_FIELDS for a merge request. Each evaluation of a merge
    # request filter must add them, because a rule on a field that the filter data does not have never matches.
    module MergeRequestFilterData
      def self.for(merge_request)
        {
          'created_by_flow' => ::Ai::DuoWorkflows::WorkflowMergeRequest.created_for_merge_request(merge_request).exists?,
          'draft' => merge_request.draft?
        }
      end
    end
  end
end
