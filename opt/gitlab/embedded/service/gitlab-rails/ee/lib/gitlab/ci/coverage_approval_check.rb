# frozen_string_literal: true

module Gitlab
  module Ci
    # Decides whether the Coverage-Check approval rule requires approval for a
    # merge request, and why.
    #
    # Shared by {Ci::SyncReportsToApprovalRulesService}, which enforces the rule,
    # and {ApprovalWrappedRule#blockage_reason}, which explains it, so that both
    # always agree. This is also the only place that evaluates the
    # `coverage_minimum_threshold` feature flag for this decision.
    class CoverageApprovalCheck
      # @!attribute [r] required?
      #   @return [Boolean] whether approval is required
      # @!attribute [r] reason
      #   @return [Symbol, nil] one of {REASONS}, or nil when approval is not required
      # @!attribute [r] coverage
      #   @return [Float, nil] coverage of the pipeline
      # @!attribute [r] threshold
      #   @return [Float, nil] minimum coverage threshold, set for `:below_threshold`
      # @!attribute [r] base_coverage
      #   @return [Float, nil] coverage of the base pipeline, set for `:decreased`
      Result = Struct.new(:required?, :reason, :coverage, :threshold, :base_coverage, keyword_init: true)

      REASONS = %i[below_threshold decreased missing_base_coverage].freeze

      NOT_REQUIRED = Result.new(required?: false).freeze

      # @param merge_request [MergeRequest]
      # @param pipeline [Ci::Pipeline, nil] head pipeline of the merge request
      # @param threshold [Float, nil] minimum coverage threshold of the rule
      # @return [Result]
      def self.check(merge_request:, pipeline:, threshold:)
        new(merge_request: merge_request, pipeline: pipeline, threshold: threshold).check
      end

      # @param merge_request [MergeRequest]
      # @param pipeline [Ci::Pipeline, nil] head pipeline of the merge request
      # @param threshold [Float, nil] minimum coverage threshold of the rule
      def initialize(merge_request:, pipeline:, threshold:)
        @merge_request = merge_request
        @pipeline = pipeline
        @threshold = threshold
      end

      # Checks the absolute threshold first, then the coverage of the base pipeline.
      #
      # @return [Result]
      def check
        coverage = pipeline&.coverage
        return NOT_REQUIRED unless coverage

        if threshold_enforced? && coverage < threshold
          return Result.new(required?: true, reason: :below_threshold, coverage: coverage, threshold: threshold)
        end

        base_pipeline = merge_request.base_pipeline
        # Without a base pipeline there is nothing to compare against, so approval is not required.
        return NOT_REQUIRED unless base_pipeline

        base_coverage = base_pipeline.coverage
        return Result.new(required?: true, reason: :missing_base_coverage, coverage: coverage) unless base_coverage

        if coverage < base_coverage
          return Result.new(required?: true, reason: :decreased, coverage: coverage, base_coverage: base_coverage)
        end

        NOT_REQUIRED
      end

      private

      attr_reader :merge_request, :pipeline, :threshold

      def threshold_enforced?
        threshold.present? && Feature.enabled?(:coverage_minimum_threshold, merge_request.target_project)
      end
    end
  end
end
