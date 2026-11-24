# frozen_string_literal: true

module Geo
  module Tools
    # SPIKE (gitlab-org/gitlab#602803): read-only wrapper around a Geo::Errors::ErrorType
    # catalog entry. Detection and resolution behaviour live in a per-strategy
    # Geo::Tools::Resolutions object that this delegates to; this class just adds the
    # catalog metadata and the site guard on top.
    class KnownError
      attr_reader :error_type

      delegate :name, :title, :description, :severity, :site, :match_pattern,
        :resolvable, :resolve_strategy, :docs, :issues, to: :error_type
      delegate :sample, :count_capped?, to: :resolution

      def initialize(error_type, **options)
        @error_type = error_type
        @options = options
      end

      # @return [Boolean] whether there are records this resolution would act on
      def detected?
        affected_count > 0
      end

      # Memoized: cleanup_check reads this once during detection and again when printing,
      # and the count does not change between those two reads.
      def affected_count
        @affected_count ||= resolution.affected_count
      end

      def runnable_on_current_site?
        return false unless resolvable

        case site
        when 'primary' then Gitlab::Geo.primary?
        when 'secondary' then Gitlab::Geo.secondary?
        else false
        end
      end

      # @return [String] affected_count for display, suffixed with "+" when the resolution
      #   stopped counting at its cap so the number is a floor rather than the total.
      def affected_count_label
        "#{affected_count}#{'+' if count_capped?}"
      end

      # Serializable form for machine-readable output (see CleanupCheckReport#to_h).
      def to_h
        {
          name: name,
          title: title,
          severity: severity,
          affected_count: affected_count,
          count_capped: count_capped?,
          match_pattern: match_pattern,
          resolvable: resolvable,
          docs: docs
        }
      end

      def resolution
        @resolution ||= Resolutions.for(error_type, **@options)
      end
    end
  end
end
