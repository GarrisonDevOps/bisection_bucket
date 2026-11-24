# frozen_string_literal: true

module Gitlab
  module Duo
    module RiskAssessment
      module Signals
        # What the merge request changes about its dependencies.
        #
        # A pinned or bumped dependency is a supply-chain-adjacent risk a path
        # pattern can name outright, unlike DiffShape or TestCoverage. Touching a
        # manifest and its lockfile together is one dependency change, so the
        # spread dimension counts ecosystems rather than files.
        class DependencyManifest < Base
          set_label N_('RiskAssessment|Dependency changes')

          add_dimension :touched, N_('RiskAssessment|Dependency files changed')
          add_dimension :direct_change, N_('RiskAssessment|Manifest file changed directly')
          add_dimension :ecosystems, N_('RiskAssessment|Number of dependency ecosystems touched')

          ECOSYSTEMS = {
            rubygems: %w[Gemfile Gemfile.lock],
            npm: %w[package.json package-lock.json yarn.lock pnpm-lock.yaml],
            go: %w[go.mod go.sum],
            cargo: %w[Cargo.toml Cargo.lock],
            composer: %w[composer.json composer.lock],
            python: %w[Pipfile Pipfile.lock requirements.txt]
          }.freeze

          LOCKFILES = %w[
            Gemfile.lock
            package-lock.json
            yarn.lock
            pnpm-lock.yaml
            go.sum
            Cargo.lock
            composer.lock
            Pipfile.lock
          ].freeze

          MANIFESTS = %w[
            Gemfile
            package.json
            go.mod
            Cargo.toml
            composer.json
            Pipfile
            requirements.txt
          ].freeze

          FILENAMES = (LOCKFILES + MANIFESTS).freeze

          ECOSYSTEMS_SATURATE_AT = 3

          def available?
            diff_stats.present?
          end

          def touched
            touched_filenames.any? ? 1.0 : 0.0
          end

          def direct_change
            direct_change? ? 1.0 : 0.0
          end

          def ecosystems
            ramp(touched_ecosystems.size - 1, ECOSYSTEMS_SATURATE_AT - 1)
          end

          private

          # A lockfile moving on its own is a transitive refresh; a manifest
          # moving is someone deciding to depend on something different.
          def direct_change?
            touched_filenames.intersect?(MANIFESTS.to_set)
          end

          def touched_ecosystems
            ECOSYSTEMS.select { |_name, filenames| touched_filenames.intersect?(filenames.to_set) }.keys
          end
          strong_memoize_attr :touched_ecosystems

          def touched_filenames
            diff_stats.paths.map { |path| File.basename(path) }.to_set & FILENAMES.to_set
          end
          strong_memoize_attr :touched_filenames

          def diff_stats
            merge_request.diff_stats
          end
          strong_memoize_attr :diff_stats
        end
      end
    end
  end
end
