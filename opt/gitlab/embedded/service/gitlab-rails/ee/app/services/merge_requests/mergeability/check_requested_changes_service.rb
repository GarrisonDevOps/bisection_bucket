# frozen_string_literal: true

module MergeRequests
  module Mergeability
    class CheckRequestedChangesService < CheckBaseService
      set_identifier :requested_changes
      set_failure_explanation N_('All requested changes must be resolved.')
      set_description 'Checks whether the merge request has changes requested'

      def execute
        return inactive unless merge_request.reviewer_requests_changes_feature

        return warning if merge_request.override_requested_changes?
        return failure if merge_request.has_changes_requested?

        success
      end

      def skip?
        params[:skip_requested_changes_check].present?
      end

      def cacheable?
        false
      end
    end
  end
end
