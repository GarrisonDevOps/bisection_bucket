# frozen_string_literal: true

module MergeRequests
  module Mergeability
    class CheckMergeRequestTitleRegexService < CheckBaseService
      include Gitlab::Utils::StrongMemoize

      set_identifier :title_regex
      set_failure_explanation N_('The title must match the required pattern.')
      set_description 'Checks whether the title matches the expected regex'

      def execute
        return inactive unless validate_title_regex?

        if valid_project_regex
          success
        else
          failure
        end
      end

      def skip?
        params[:skip_merge_request_title_check].present?
      end

      def cacheable?
        false
      end

      private

      def valid_project_regex
        regexp = Gitlab::UntrustedRegexp.new(project_regex)
        # Strip any draft prefix (e.g. "Draft:" / "[Draft]" / "(Draft)") before matching so
        # that marking an MR as draft does not cause a spurious title-pattern
        # failure; draft status is already surfaced by its own merge check.
        title = ::MergeRequest.draftless_title(merge_request.title)

        regexp === title
      end

      def validate_title_regex?
        project.licensed_feature_available?(:merge_request_title_regex_check) &&
          project_regex.present?
      end

      def project
        merge_request.project
      end

      def project_regex
        project.merge_request_title_regex
      end
      strong_memoize_attr :project_regex
    end
  end
end
