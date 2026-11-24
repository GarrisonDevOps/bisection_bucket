# frozen_string_literal: true

module MergeRequests
  module Mergeability
    class CheckExternalStatusChecksPassedService < CheckBaseService
      set_identifier :status_checks_must_pass
      set_failure_explanation N_('All external status checks must pass.')
      set_description 'Checks whether the external status checks pass'

      def execute
        return inactive unless only_allow_merge_if_all_status_checks_passed_enabled?(merge_request.project)

        if prevent_merge_unless_status_checks_passed?
          failure
        else
          success
        end
      end

      def skip?
        params[:skip_external_status_check].present?
      end

      def cacheable?
        false
      end

      private

      def prevent_merge_unless_status_checks_passed?
        merge_request.project.any_external_status_checks_not_passed?(merge_request)
      end

      def only_allow_merge_if_all_status_checks_passed_enabled?(project)
        project.licensed_feature_available?(:external_status_checks) &&
          project.only_allow_merge_if_all_status_checks_passed
      end
    end
  end
end
