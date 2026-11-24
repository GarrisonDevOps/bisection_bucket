# frozen_string_literal: true

module Gitlab
  module Duo
    module RiskAssessment
      module Signals
        # Proportion of the merge request's commits written by an agent.
        #
        # Detection relies on the Duo-Session commit trailer, so recall is low
        # by construction: it only sees Duo Agent Platform commits, only when
        # the project has session tracking enabled, and never sees
        # IDE-assisted human commits. The scoring function therefore caps this
        # signal's contribution -- it is a nudge, not a verdict, and treating
        # it as one would penalise the wrong authors.
        class AiAuthorship < Base
          set_label N_('RiskAssessment|Commit authorship')

          add_dimension :agent_authored, N_('RiskAssessment|Agent-authored commits')

          def available?
            !!project.project_setting&.dap_session_tracking_enabled?
          end

          def agent_authored
            return 0.0 if commits.empty?

            # Commit#has_agent_session? falls back to matching safe_message
            # when trailers are not loaded, so no extra Gitaly fetch is needed.
            agent_authored_count = commits.count(&:has_agent_session?)

            (agent_authored_count.to_f / commits.size).round(4)
          end

          private

          def commits
            merge_request.commits(load_from_gitaly: true).to_a
          end
          strong_memoize_attr :commits
        end
      end
    end
  end
end
