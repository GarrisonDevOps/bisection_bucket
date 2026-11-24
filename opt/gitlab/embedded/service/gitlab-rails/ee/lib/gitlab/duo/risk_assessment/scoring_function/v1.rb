# frozen_string_literal: true

module Gitlab
  module Duo
    module RiskAssessment
      module ScoringFunction
        # Turns categorical claims and deterministic signals into a score and a
        # confidence.
        #
        # Pure and deterministic on purpose. The classification flow supplies
        # only categorical answers; the arithmetic lives here, in code, under
        # review, with a version stamped onto every assessment. That is what
        # makes a score auditable, reproducible across runs, and retunable later
        # against real outcomes.
        #
        # The weights below are a starting point, not a calibration. They are
        # not fitted to outcome data yet, because there is none to fit to.
        class V1 < Base
          include ::Gitlab::Utils::StrongMemoize

          self.version = 'v1'

          # Absolute points out of 100. The spec over every version is what
          # holds these to that total.
          #
          # Claims carry most of the weight because they read intent, which
          # nothing measurable can. A path can tell that a migration file
          # changed; only a claim can tell an index rename from a column drop.
          #
          # `api_contract` is scored below what its severity suggests because
          # the question is only whether the contract was touched: most such
          # changes are additive and safe. Grading a domain answer, here or
          # for `database_migration`, is a later version.
          weigh_domain :authorization, 21
          weigh_domain :credentials_crypto, 17
          weigh_domain :authentication, 14
          weigh_domain :database_migration, 14
          weigh_domain :api_contract, 8

          # Structural signals are weak individually: a large mechanical rename
          # is not risky. They are kept small so they can corroborate the
          # claims without overruling them.
          #
          # A dimension with no weight here is measured but not scored. That is
          # deliberate: a dimension earns weight only once we can say what it
          # is worth.
          weigh_signal :test_coverage, :uncovered_lines, 5
          weigh_signal :test_evidence, :untested, 4
          weigh_signal :reversibility, :destructive, 4
          weigh_signal :diff_shape, :churn, 3
          weigh_signal :diff_shape, :breadth, 2
          weigh_signal :diff_shape, :dispersion, 1
          weigh_signal :ownership, :unowned, 2
          weigh_signal :ownership, :author_not_owner, 1
          weigh_signal :author_experience, :unfamiliar_author, 2
          weigh_signal :dependency_manifest, :direct_change, 1
          weigh_signal :ai_authorship, :agent_authored, 1

          # Mitigations subtract. They are capped well below the claim budget so
          # that wrapping a risky change in a feature flag cannot talk the score
          # down to nothing.
          weigh_mitigation :revert, :reverts_prior_change, 8
          weigh_mitigation :rollout_guard, :feature_flag, 6

          MITIGATION_CAP = 12

          # Names the cap line in the breakdown. Not a registered signal, so a
          # reader resolves no label for it and has to recognise it by name.
          # Mirrored by MITIGATION_CAP_SIGNAL in the MR widget's risk_classification/constants.js; rename both together.
          MITIGATION_CAP_SIGNAL = 'mitigation_cap'

          # The only answers a boolean claim recognises. The flow returns
          # free-form text, and anything else has to read as unanswered rather
          # than as the safe answer.
          BOOLEAN_CLAIM_VALUES = %w[true false].freeze

          # The two halves of confidence; they sum to 1. Availability counts
          # how much of the budget was answered. Agreement checks if claims and
          # measured signals match. Availability weighs more: a full but
          # disagreeing picture beats a thin one.
          AVAILABILITY_WEIGHT = 0.65
          AGREEMENT_WEIGHT = 0.35

          def execute
            Result.new(
              score: score,
              confidence: confidence,
              signal_breakdown: breakdown,
              version: version,
              missing_signals: missing_inputs
            )
          end

          private

          def score
            total = claim_points + signal_points - mitigation_points

            total.round.clamp(Thresholds::MIN_SCORE, Thresholds::MAX_SCORE)
          end

          # Confidence answers "how much of the picture did we actually see, and
          # did the parts we saw agree?". It never moves the score: an uncertain
          # assessment is not the same thing as a risky one.
          def confidence
            weighted = if comparable?
                         (AVAILABILITY_WEIGHT * availability) + (AGREEMENT_WEIGHT * agreement)
                       else
                         availability
                       end

            (100 * weighted).round
          end

          def breakdown
            (claim_contributions + signal_contributions + mitigation_contributions + cap_adjustment)
              .sort_by { |contribution| -contribution[:contribution].abs }
              .map(&:stringify_keys)
          end

          def missing_inputs
            missing_claims = claim_weights.keys.reject { |key| claim_answered?(key) }

            (missing + missing_claims).uniq
          end

          def claim_points
            sum_contributions(claim_contributions)
          end

          def signal_points
            sum_contributions(signal_contributions)
          end

          def mitigation_points
            [sum_contributions(mitigation_contributions).abs, MITIGATION_CAP].min
          end

          def sum_contributions(contributions)
            contributions.sum { |contribution| contribution[:contribution] }
          end

          def claim_contributions
            claim_weights.filter_map do |key, config|
              value = claim_value(key)
              next if value.nil?

              fraction = claim_fraction(config, value)
              next if fraction <= 0

              # Skip anything that rounds away to nothing: a persisted 0.0 row
              # reads as "changed nothing" while still taking up space.
              points = (config[:max] * fraction).round(2)
              next if points == 0

              {
                signal: key,
                contribution: points,
                detail: claim_detail(key, value)
              }
            end
          end
          strong_memoize_attr :claim_contributions

          def signal_contributions
            weighted_contributions(signal_weights, signals)
          end
          strong_memoize_attr :signal_contributions

          # Negative by construction, so the breakdown shows what pulled the
          # score down as plainly as what pushed it up.
          def mitigation_contributions
            weighted_contributions(mitigation_weights, mitigations, sign: -1)
          end
          strong_memoize_attr :mitigation_contributions

          # Mitigations are reported at what they are worth, but the score only
          # drops by the cap. Without this line the breakdown would overstate what
          # they achieved and stop adding up to the score it explains.
          #
          # Carries no sentence of its own: the breakdown is persisted, so
          # prose here would be frozen in the locale of whichever process
          # scored it. The reader composes it from MITIGATION_CAP instead.
          def cap_adjustment
            forgone = sum_contributions(mitigation_contributions).abs - MITIGATION_CAP
            return [] if forgone <= 0

            [{ signal: MITIGATION_CAP_SIGNAL, contribution: forgone.round(2), detail: nil }]
          end

          # Values arrive normalised, and a value above 1.0 would award a
          # weight more than it is worth, so the contract is enforced here
          # rather than trusted.
          def weighted_contributions(weights, values, sign: 1)
            weights.filter_map do |key, max|
              value = values[key].to_f.clamp(0.0, 1.0)
              next if value <= 0

              # Skip anything that rounds away to nothing: a persisted 0.0 row
              # reads as "changed nothing" while still taking up space.
              points = (max * value).round(2)
              next if points == 0

              { signal: key, contribution: sign * points, detail: nil }
            end
          end

          # Anything we could not measure lowers confidence. A signal that
          # reported itself unavailable must not read the same as one that
          # measured zero risk.
          #
          # Counted in points rather than in inputs, because the inputs are not
          # worth the same: an unanswered 21-point claim leaves far more of the
          # picture unseen than an unmeasured 1-point dimension. Mitigations are
          # left out on purpose, since they subtract from the budget rather than
          # make it up.
          def availability
            expected = self.class.claim_budget + self.class.signal_budget
            return 0.0 if expected == 0

            ((answered_claim_budget + answered_signal_budget) / expected.to_f).clamp(0.0, 1.0)
          end

          def answered_claim_budget
            claim_weights.sum { |key, config| claim_answered?(key) ? self.class.claim_ceiling(config) : 0 }
          end
          strong_memoize_attr :answered_claim_budget

          def answered_signal_budget
            signal_weights.sum { |key, max| signals.key?(key) ? max : 0 }
          end
          strong_memoize_attr :answered_signal_budget

          # Agreement only means something when both halves were measured.
          # Comparing a measured half against an unmeasured one reads as
          # disagreement, which would penalise answering claims at all, so
          # confidence falls back to availability alone in that case.
          def comparable?
            semantic_measured? && structural_measured?
          end

          def semantic_measured?
            answered_claim_budget > 0
          end

          def structural_measured?
            answered_signal_budget > 0
          end

          # Independent halves of the assessment: what the flow concluded
          # semantically, and what the repository measurably looks like. When
          # they disagree, we are less sure of the answer.
          def agreement
            (1.0 - (semantic_fraction - structural_fraction).abs).clamp(0.0, 1.0)
          end

          # Measured against what was actually answered, not the whole budget.
          # An unanswered claim scores nothing, so dividing by the full budget
          # would read those blanks as the flow disagreeing with the signals -
          # and availability already accounts for them.
          def semantic_fraction
            fraction_of(claim_points, answered_claim_budget)
          end

          def structural_fraction
            fraction_of(signal_points, answered_signal_budget)
          end

          def fraction_of(points, budget)
            return 0.0 if budget == 0

            (points / budget.to_f).clamp(0.0, 1.0)
          end

          # An answer the weight cannot interpret is unanswered, not safe. The
          # flow's value is free-form text, so a drifted answer like "yes" would
          # otherwise score zero while reporting the domain as fully assessed -
          # indistinguishable from "this domain is not touched".
          def claim_answered?(key)
            value = claim_value(key)
            return false if value.nil?

            config = claim_weights[key]
            return config[:scale].key?(value.to_s) if config[:scale]

            BOOLEAN_CLAIM_VALUES.include?(value.to_s)
          end

          def claim_hash(key)
            claim = claims[key]
            claim.is_a?(Hash) ? claim.stringify_keys : {}
          end

          def claim_value(key)
            claim_hash(key)['value']
          end

          def claim_fraction(config, value)
            return config[:scale].fetch(value.to_s, 0.0) if config[:scale]

            truthy?(value) ? 1.0 : 0.0
          end

          def truthy?(value)
            [true, 'true'].include?(value)
          end

          # Evidence is written by the model, so it is collapsed onto one line:
          # this string is persisted and later rendered as the explanation of a
          # score, and newlines there would break out of it.
          def claim_detail(key, value)
            evidence = claim_hash(key)['evidence']
            return "#{key}: #{value}" if evidence.blank?

            "#{key}: #{value} (#{evidence.to_s.squish})"
          end
        end
      end
    end
  end
end
