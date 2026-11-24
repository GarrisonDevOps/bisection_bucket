# frozen_string_literal: true

module Gitlab
  module GrapeOpenapi
    # A Grape route pattern rendered as an OpenAPI path template.
    #
    # Grape spells path placeholders two ways: `:name` matches a single segment,
    # and `*name` (a splat) matches one or more segments, so its value may contain
    # slashes. OpenAPI 3.0 has no splat syntax, so both collapse to `{name}`.
    #
    # The splat mapping is lossy - `{name}` implies a single segment - but the
    # endpoint is documented, which is strictly better than omitting it. Do not
    # "fix" this by dropping splat routes: that is the bug in issue #22, which
    # silently removed the entire package registry surface from the spec.
    class NormalizedPath
      # Grape appends the format suffix to `route.path`, not to `route.pattern.origin`,
      # so this only strips a suffix an author wrote into the pattern by hand. Without
      # it, a declared `format` param would be mistaken for a path parameter.
      FORMAT_SUFFIX = /\(\.:format\)$/

      PLACEHOLDER = /[:*](\w+)/
      NORMALIZED_PLACEHOLDER = /\{(\w+)\}/

      # Grape's optional-segment markup: the parentheses grouping an optional
      # segment, and the backslashes escaping a literal parenthesis. Both are
      # noise once a path is rendered for a human.
      OPTIONAL_SEGMENT_MARKUP = /[()\\]/

      # The API version is substituted away with the configured value before a path
      # is emitted, so it never surfaces as a path parameter.
      API_VERSION_PLACEHOLDER = 'version'

      attr_reader :origin

      # Takes a `route.pattern.origin` - the pattern as the author declared it.
      # Do not pass `route.path`: Grape rewrites that one, appending the format
      # suffix and turning a trailing `*path` into `?*path`.
      def initialize(origin)
        @origin = origin
      end

      def to_s
        @to_s ||= origin
          .sub(FORMAT_SUFFIX, '')
          .gsub(PLACEHOLDER) { "{#{Regexp.last_match(1)}}" }
      end

      # The path as shown to humans in emitted paths and warnings: placeholders
      # collapsed (via `to_s`), optional-segment markup removed, and the API
      # version substituted in for `{version}`.
      def to_display_path(api_version)
        to_s.gsub(OPTIONAL_SEGMENT_MARKUP, '').gsub("{#{API_VERSION_PLACEHOLDER}}", api_version)
      end

      def placeholder_names
        # Scanning whole `{name}` placeholders sidesteps the boundary problem a regex
        # over the raw pattern has: real routes introduce a placeholder after `/`,
        # `(`, `)` and `'` - `(*path`, `):file_name`, `Id='*package_name'` - so there
        # is no single delimiter to anchor on.
        @placeholder_names ||= to_s.scan(NORMALIZED_PLACEHOLDER).flatten
      end

      def path_parameter_names
        placeholder_names - [API_VERSION_PLACEHOLDER]
      end
    end
  end
end
