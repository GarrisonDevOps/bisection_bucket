# frozen_string_literal: true

module Gitlab
  module Duo
    module RiskAssessment
      module Signals
        # Whether the change brought tests with it.
        #
        # Complements TestCoverage rather than duplicating it. TestCoverage needs a
        # code_coverage artifact on a finished pipeline, and classification
        # runs when the merge request opens, so on most merge requests it
        # reports unavailable. This reads paths alone and is always answerable.
        class TestEvidence < Base
          set_label N_('RiskAssessment|Test evidence')

          add_dimension :untested, N_('RiskAssessment|Source changes without a matching test')

          TEST_PATH = Regexp.union(
            %r{\A(ee/|jh/)?(spec|test|tests|qa)/},
            %r{(\A|/)__tests__/},
            %r{_(spec|test)\.rb\z},
            %r{\.(spec|test)\.(js|ts|jsx|tsx|vue)\z},
            %r{_test\.go\z},
            %r{(\A|/)test_[^/]+\.py\z}
          )

          # Prose, fixtures and configuration are not expected to ship tests,
          # so counting them as untested source would flag docs-only changes.
          NON_SOURCE_PATH = Regexp.union(
            %r{\A(ee/|jh/)?(doc|docs|locale|changelogs)/},
            %r{\.(md|markdown|txt|json|ya?ml|toml|lock|svg|png|jpg|gif|ico)\z},
            %r{\A\.[^/]+\z}
          )

          def available?
            changed_paths.present?
          end

          def untested
            return 0.0 if source_paths.empty?

            covered = [test_paths.size.to_f / source_paths.size, 1.0].min

            (1.0 - covered).round(4)
          end

          private

          def test_paths
            changed_paths.select { |path| path.match?(TEST_PATH) }
          end
          strong_memoize_attr :test_paths

          def source_paths
            changed_paths.reject { |path| path.match?(TEST_PATH) || path.match?(NON_SOURCE_PATH) }
          end
          strong_memoize_attr :source_paths
        end
      end
    end
  end
end
