# frozen_string_literal: true

module ArtifactRegistry
  module Permissions
    class VerdictReport
      LIFETIME = 1.hour
      MEMO_KEY_PREFIX = 'artifact_registry:verdict_report'

      AbsentError = Class.new(StandardError)
      DriftError = Class.new(StandardError)
      DefectError = Class.new(StandardError)

      def self.absent(verdicts)
        report(
          AbsentError.new('Artifact Registry answered a permissions read without a permissions object'),
          memo: [:absent, verdicts.read, verdicts.slug],
          read: verdicts.read, slug: verdicts.slug
        )
      end

      def self.drift(verdicts)
        report(
          DriftError.new('Artifact Registry permissions object lacks actions of its set'),
          memo: [:drift, verdicts.read, verdicts.slug],
          read: verdicts.read, slug: verdicts.slug, missing_actions: verdicts.missing_actions
        )
      end

      def self.defect(scope:)
        report(
          DefectError.new('Artifact Registry permissions block resolved without a permissions read'),
          memo: [:defect, scope],
          scope: scope
        )
      end

      def self.report(error, memo:, **context)
        key = [MEMO_KEY_PREFIX, *memo].join(':')

        Gitlab::ProcessMemoryCache.cache_backend.fetch(key, expires_in: LIFETIME) do
          Gitlab::ErrorTracking.track_exception(error, context)
          true
        end

        nil
      end
      private_class_method :report
    end
  end
end
