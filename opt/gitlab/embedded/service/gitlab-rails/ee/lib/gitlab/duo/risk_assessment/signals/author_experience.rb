# frozen_string_literal: true

module Gitlab
  module Duo
    module RiskAssessment
      module Signals
        # How much the author has shipped in this project before.
        #
        # Author experience is one of the five dimensions the just-in-time
        # defect prediction literature builds on, and it is the one GitLab can
        # answer without touching the repository. Counting is bounded by the
        # saturation point, so the query cost does not grow with prolific
        # authors.
        class AuthorExperience < Base
          set_label N_('RiskAssessment|Author experience')

          add_dimension :unfamiliar_author, N_('RiskAssessment|How new the author is to this project')

          MERGED_SATURATES_AT = 20

          def available?
            merge_request.author_id.present?
          end

          def unfamiliar_author
            (1.0 - ramp(merged_count, MERGED_SATURATES_AT)).round(4)
          end

          private

          def merged_count
            project.merge_requests
              .merged
              .authored(merge_request.author_id)
              .limit(MERGED_SATURATES_AT)
              .count
          end
        end
      end
    end
  end
end
