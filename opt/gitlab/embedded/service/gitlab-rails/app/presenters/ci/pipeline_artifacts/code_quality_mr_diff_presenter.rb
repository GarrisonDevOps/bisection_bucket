# frozen_string_literal: true

module Ci
  module PipelineArtifacts
    class CodeQualityMrDiffPresenter < Gitlab::View::Presenter::Delegated
      include Gitlab::Utils::StrongMemoize

      def for_files(merge_request)
        filenames = merge_request.new_paths
        mr_diff_report = raw_report(merge_request.id)
        quality_files = mr_diff_report["files"]&.select { |key| filenames.include?(key) }

        { files: quality_files }
      end

      def readable_by?(user)
        source_access_readable_by?(user, parsed_report[Ci::PipelineArtifact::SOURCE_ACCESS_KEY])
      end

      private

      def raw_report(merge_request_id)
        parsed_report.with_indifferent_access.fetch("merge_request_#{merge_request_id}", {})
      end

      def parsed_report
        self.each_blob do |blob|
          Gitlab::Json.parse(blob)
        end
      end
      strong_memoize_attr :parsed_report
    end
  end
end
