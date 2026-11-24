# frozen_string_literal: true

module Geo
  module Tools
    module Resolutions
      # SPIKE (gitlab-org/gitlab#602803): base for known-error resolutions. A resolution
      # knows how to count and sample the records it would act on and how to apply its fix.
      # AR access lives here (model layer) rather than in the calling service.
      class Base
        BATCH_SIZE = 1_000

        # options carries per-run knobs a strategy may support (for example
        # min_retry_count). Strategies that take none simply ignore it, which keeps
        # Resolutions.for a single call shape for every entry in the catalog.
        def initialize(error_type, **options)
          @error_type = error_type
          @options = options
        end

        # @return [Integer] number of records this resolution would act on
        def affected_count
          raise Gitlab::AbstractMethodError
        end

        # Whether affected_count stopped short of the real total. Strategies that count
        # without a bound leave this false; the caller renders "N+" when it is true so an
        # operator does not read a capped number as the whole blast radius.
        def count_capped?
          false
        end

        # @return [Array<String>] human-readable lines describing a bounded sample
        def sample(...)
          raise Gitlab::AbstractMethodError
        end

        # Apply the resolution.
        # @return [Integer] number of records acted on
        def apply(...)
          raise Gitlab::AbstractMethodError
        end

        # @return [String] success message for a completed real run
        def summary(...)
          raise Gitlab::AbstractMethodError
        end

        private

        attr_reader :error_type, :options

        # uniq: several replicators can share one registry class (for example every upload
        # replicator maps to Geo::UploadRegistry), and scanning the same registry twice would
        # double-count affected rows.
        def registry_classes
          Gitlab::Geo.replication_enabled_replicator_classes.map(&:registry_class).uniq
        end

        def log(message, **extra)
          ::Gitlab::Geo::Logger.info(message: message, resolution: self.class.name, **extra)
        end
      end
    end
  end
end
