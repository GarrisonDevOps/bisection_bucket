# frozen_string_literal: true

module Gitlab
  module Duo
    module RiskAssessment
      module Signals
        # Test coverage on the lines this merge request changed.
        #
        # This is the one signal in the epic's list that GitLab already
        # computes per line and per path, so it needs no new infrastructure.
        # The pipeline artifact is read directly rather than through
        # Ci::GenerateCoverageReportsService, because that service is
        # reactive-cached and would return :parsing on a first call from a
        # worker.
        class TestCoverage < Base
          set_label N_('RiskAssessment|Test coverage')

          add_dimension :uncovered_lines, N_('RiskAssessment|Uncovered changed lines')

          def available?
            covered_files.present?
          end

          def uncovered_lines
            reported = covered_files.values.flat_map(&:values).compact
            return 0.0 if reported.empty?

            uncovered = reported.count { |hits| hits.to_i == 0 }

            (uncovered.to_f / reported.size).round(4)
          end

          private

          # Only the changed paths that the coverage report knows about. When
          # none of them appear, we genuinely cannot tell whether the change is
          # covered, so the signal reports unavailable rather than zero.
          def covered_files
            return {} unless artifact

            artifact.present.for_files(merge_request.modified_paths)[:files]
          end
          strong_memoize_attr :covered_files

          def artifact
            merge_request.diff_head_pipeline&.pipeline_artifacts&.find_by_file_type(:code_coverage)
          end
          strong_memoize_attr :artifact
        end
      end
    end
  end
end
