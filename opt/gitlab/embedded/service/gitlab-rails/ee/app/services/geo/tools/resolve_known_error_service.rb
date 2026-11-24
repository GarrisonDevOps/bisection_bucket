# frozen_string_literal: true

module Geo
  module Tools
    # SPIKE (gitlab-org/gitlab#602803): resolves a known Geo error by applying its catalog
    # resolution strategy.
    #
    # Dry run by default (the rake task only acts when DRY_RUN=false). The same flag gates
    # the destructive strategies (for example delete_orphaned_uploads); the
    # count and sample shown by the caller are the operator's safety check before a real
    # run. The actual detection and mutation live in the per-strategy Geo::Tools::Resolutions
    # object; this service just orchestrates the site guard and the dry-run gate.
    #
    # Expects a single KnownError instance: it reads the count and then applies through the
    # same object, so that instance's memoized count and resolution stay in step.
    class ResolveKnownErrorService
      def initialize(known_error, dry_run: true, limit: nil)
        @known_error = known_error
        @dry_run = dry_run
        @limit = limit
      end

      def execute
        return skip_response unless known_error.runnable_on_current_site?

        count = known_error.affected_count
        return empty_response if count == 0
        return dry_run_response(count, known_error.affected_count_label) if dry_run

        resolved = known_error.resolution.apply(limit: limit)
        success(known_error.resolution.summary(resolved), resolved)
      end

      private

      attr_reader :known_error, :dry_run, :limit

      # label carries the "+" suffix when the resolution capped its count; the payload keeps the
      # plain integer so callers can still do arithmetic on it.
      def dry_run_response(count, label)
        ServiceResponse.success(
          message: "Dry run: #{label} records would be affected. Re-run with DRY_RUN=false to resolve.",
          payload: { count: count, dry_run: true }
        )
      end

      def empty_response
        ServiceResponse.success(message: "No affected records found.", payload: { count: 0 })
      end

      def skip_response
        ServiceResponse.error(
          message: "Not resolvable on this site. This error resolves on the #{known_error.site} site.",
          reason: :not_runnable_on_site
        )
      end

      def success(message, count)
        ServiceResponse.success(message: message, payload: { count: count, dry_run: false })
      end
    end
  end
end
