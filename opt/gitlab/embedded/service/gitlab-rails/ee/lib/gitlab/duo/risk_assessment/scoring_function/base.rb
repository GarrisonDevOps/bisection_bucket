# frozen_string_literal: true

module Gitlab
  module Duo
    module RiskAssessment
      module ScoringFunction
        # What every scoring version accepts and returns, apart from what any
        # one of them calculates. A caller has to be able to read a result
        # without knowing which version made it, so the inputs and the result
        # shape are fixed here and the arithmetic is not.
        class Base
          # Every version declares weights against the same signal and domain
          # registries. The declarations are part of the contract, even though
          # the numbers in them are not.
          include Weights

          class_attribute :version, instance_predicate: false

          Result = Struct.new(
            # An integer from 0 to 100. A threshold table turns this
            # into a risk tier, so tiers can change without rescoring.
            :score,
            # An integer from 0 to 100. How much of the picture we saw.
            # Kept apart from score: unsure is not the same as safe.
            :confidence,
            # What each input added to the score, largest first. A
            # score a reviewer cannot question is trusted by no one.
            :signal_breakdown,
            # Weights change over time, so only scores from the same
            # version compare.
            :version,
            # Inputs we could not check at all. Kept apart from
            # inputs scored as safe, so "unknown" never reads as "safe".
            :missing_signals,
            keyword_init: true
          )

          # @param claims [Hash] categorical claims from the flow, keyed by claim
          #   name, each { 'value' => ..., 'evidence' => ... }
          # @param signals [Hash] normalised 0..1 values from SignalsExtractor
          # @param mitigations [Hash] normalised 0..1 values that reduce the score
          # @param missing [Array<String>] signals that could not be measured
          def initialize(claims: {}, signals: {}, mitigations: {}, missing: [])
            @claims = (claims || {}).stringify_keys
            @signals = (signals || {}).stringify_keys
            @mitigations = (mitigations || {}).stringify_keys
            @missing = Array(missing).map(&:to_s)
          end

          # A version that forgets to score must fail loudly. An empty result
          # would read as "nothing risky here".
          #
          # @return [Result]
          def execute
            raise ::Gitlab::AbstractMethodError
          end

          private

          attr_reader :claims, :signals, :mitigations, :missing
        end
      end
    end
  end
end
