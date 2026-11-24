# frozen_string_literal: true

module Gitlab
  module Duo
    module RiskAssessment
      module Signals
        # Who owns the code this merge request changes, from CODEOWNERS.
        #
        # Ownership is one of the better-evidenced predictors of failure-prone
        # code, and GitLab has it declared rather than having to mine it from
        # history. Unowned code and code the author does not own are both
        # harder to review well; a change spread across many owners is a
        # coordination problem before it is a correctness one.
        class Ownership < Base
          set_label N_('RiskAssessment|Code ownership')

          add_dimension :unowned, N_('RiskAssessment|Changed paths with no declared owner')
          add_dimension :author_not_owner, N_('RiskAssessment|Author does not own the changed code')
          add_dimension :owner_spread, N_('RiskAssessment|Number of distinct owners')

          OWNERS_SATURATE_AT = 5

          def available?
            project.licensed_feature_available?(:code_owners) && changed_paths.present? && !loader.empty_code_owners?
          end

          def unowned
            entries.empty? ? 1.0 : 0.0
          end

          def author_not_owner
            author_owns_any? ? 0.0 : 1.0
          end

          def owner_spread
            ramp(distinct_owners - 1, OWNERS_SATURATE_AT - 1)
          end

          private

          def loader
            ::Gitlab::CodeOwners::Loader.new(project, merge_request.target_branch_ref, changed_paths)
          end
          strong_memoize_attr :loader

          # Entries matched against every changed path, with their users and
          # groups already resolved by the loader.
          def entries
            loader.entries
          end
          strong_memoize_attr :entries

          def author_owns_any?
            return false unless merge_request.author_id

            entries.any? { |entry| entry.all_users(project).any? { |user| user.id == merge_request.author_id } }
          end

          # Owner lines rather than sections: most CODEOWNERS files declare no
          # sections at all, so sections would read as one owner everywhere.
          def distinct_owners
            entries.map(&:owner_line).uniq.size
          end
        end
      end
    end
  end
end
