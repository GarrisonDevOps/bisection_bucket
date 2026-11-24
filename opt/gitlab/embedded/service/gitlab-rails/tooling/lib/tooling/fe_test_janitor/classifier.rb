# frozen_string_literal: true

require_relative 'signals'
require_relative 'example_parser'

module Tooling
  module FeTestJanitor
    # Classifies a single RSpec example as :migrate, :reframe, :partial, or :keep.
    # A shared example call is :shared, because its body lives in another file.
    #
    # Decision logic:
    #   - Collect all matching keep, reframe, and migrate signals from the body.
    #   - If keep and migrate signals match -> :partial
    #   - If keep signals match             -> :keep
    #   - If reframe signals match          -> :reframe (assert the UI, not the DB)
    #   - If migrate signals match          -> :migrate
    #   - If nothing matches                -> :keep (default: assume server-side until proven otherwise)
    class Classifier
      Result = Struct.new(:verdict, :reasons, keyword_init: true)

      def classify(example)
        return Result.new(verdict: :shared, reasons: ['shared example call, not analyzed']) if example.shared

        keep_reasons    = matching_reasons(example.body, Signals::KEEP)
        reframe_reasons = matching_reasons(example.body, Signals::REFRAME)
        migrate_reasons = matching_reasons(example.body, Signals::MIGRATE)

        verdict =
          if keep_reasons.any? && migrate_reasons.any?
            :partial
          elsif keep_reasons.any?
            :keep
          elsif reframe_reasons.any?
            :reframe
          elsif migrate_reasons.any?
            :migrate
          else
            # No signals detected - default to keep (conservative).
            :keep
          end

        Result.new(verdict: verdict, reasons: (keep_reasons + reframe_reasons + migrate_reasons).uniq)
      end

      private

      def matching_reasons(body, signal_list)
        signal_list.each_with_object([]) do |signal, acc|
          acc << signal[:reason] if signal[:pattern].match?(body)
        end
      end
    end
  end
end
