# frozen_string_literal: true

module Gitlab
  module Duo
    module RiskAssessment
      module Signals
        # Size and scatter of the change, from a single Gitaly DiffStats call.
        #
        # These are weak signals on their own -- a large mechanical rename is
        # not risky -- which is why the scoring function only lets them
        # contribute a small amount and leans on the flow's behavioral-versus-
        # cosmetic claim to tell the two apart.
        class DiffShape < Base
          set_label N_('RiskAssessment|Change shape')

          add_dimension :churn, N_('RiskAssessment|Size of change')
          add_dimension :breadth, N_('RiskAssessment|Number of files changed')
          add_dimension :dispersion, N_('RiskAssessment|Spread across subsystems')
          add_dimension :entropy, N_('RiskAssessment|Concentration of the change across files')
          add_dimension :net_growth, N_('RiskAssessment|Proportion of added to removed lines')

          LINES_SATURATE_AT = 500
          FILES_SATURATE_AT = 30
          DIRECTORIES_SATURATE_AT = 6

          # Machine-written files inflate every size measure without adding
          # anything a reviewer has to reason about. Checking .gitattributes
          # for gitlab-generated/linguist-generated would be more accurate but
          # costs extra Gitaly round trips, so match on path instead.
          GENERATED_PATH_PATTERNS = [
            %r{(\A|/)db/structure\.sql\z},
            %r{(\A|/)(vendor|node_modules)/},
            %r{(\A|/)__snapshots__/},
            %r{\.lock\z},
            %r{(\A|/)(go\.sum|yarn\.lock|pnpm-lock\.yaml)\z},
            %r{-lock\.json\z},
            %r{\.(min\.js|min\.css|pb\.go|generated\.\w+)\z}
          ].freeze

          def available?
            diff_stats.present?
          end

          def churn
            ramp(lines_changed, LINES_SATURATE_AT)
          end

          def breadth
            ramp(paths.size, FILES_SATURATE_AT)
          end

          def dispersion
            ramp(top_level_directories.size - 1, DIRECTORIES_SATURATE_AT - 1)
          end

          # Shannon entropy over each file's share of the changed lines,
          # normalized to 0..1. Distinguishes a change concentrated in one file
          # from the same line count spread evenly, which the file and
          # directory counts alone cannot.
          def entropy
            return 0.0 if authored_stats.size < 2 || lines_changed == 0

            shares = authored_stats.map { |stat| (stat.additions + stat.deletions).to_f / lines_changed }
            bits = shares.sum { |share| share > 0 ? -share * Math.log2(share) : 0.0 }

            (bits / Math.log2(authored_stats.size)).round(4)
          end

          # Deletion-dominant changes remove behavior that already shipped;
          # addition-dominant ones introduce behavior that has never run.
          def net_growth
            additions = authored_stats.sum(&:additions)
            return 0.0 if lines_changed == 0

            (additions.to_f / lines_changed).round(4)
          end

          private

          def diff_stats
            merge_request.diff_stats
          end
          strong_memoize_attr :diff_stats

          # Generated files still count as touched elsewhere (DependencyManifest
          # reports lockfiles), they just do not count as shape here.
          def authored_stats
            diff_stats.reject { |stat| GENERATED_PATH_PATTERNS.any? { |pattern| stat.path.match?(pattern) } }
          end
          strong_memoize_attr :authored_stats

          def lines_changed
            authored_stats.sum { |stat| stat.additions + stat.deletions }
          end

          def paths
            authored_stats.map(&:path)
          end
          strong_memoize_attr :paths

          # A change confined to one subsystem is easier to reason about than
          # the same number of lines spread across unrelated ones.
          def top_level_directories
            paths.map { |path| path.split('/').first }.uniq
          end
        end
      end
    end
  end
end
