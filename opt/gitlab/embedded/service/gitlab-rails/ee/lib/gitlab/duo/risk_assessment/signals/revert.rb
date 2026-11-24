# frozen_string_literal: true

module Gitlab
  module Duo
    module RiskAssessment
      module Signals
        # Whether the merge request undoes a change that already shipped.
        #
        # A mitigation: a revert restores a state that ran in production, and
        # holding one in a review queue is usually worse than merging it.
        # Detection follows the conventions Commit#revert_branch_name and
        # Commit#revert_description write, so it costs nothing beyond the
        # attributes already loaded.
        class Revert < Base
          set_label N_('RiskAssessment|Revert')

          add_dimension :reverts_prior_change, N_('RiskAssessment|Reverts a previously merged change')

          BRANCH = /\Arevert-\h{7,40}\z/
          TITLE = /\ARevert\s+"/
          DESCRIPTION = /This reverts (commit \h{7,40}|merge request !\d+)/

          mitigation!

          def available?
            true
          end

          def reverts_prior_change
            revert? ? 1.0 : 0.0
          end

          private

          def revert?
            merge_request.source_branch.to_s.match?(BRANCH) ||
              merge_request.title.to_s.match?(TITLE) ||
              merge_request.description.to_s.match?(DESCRIPTION)
          end
        end
      end
    end
  end
end
