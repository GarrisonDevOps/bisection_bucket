# frozen_string_literal: true

module Labkit
  module Logging
    module FieldValidator
      module LogInterceptor
        IGNORE_PATHS = [
          %r{/gems/logger-},
          %r{/lib/labkit/logging/},
          %r{/gems/rspec-},
          %r{/ruby/\d+\.\d+\.\d+/}
        ].freeze

        LOGGER_WRAPPER_PATTERNS = [
          %r{/.*logger\.rb$}
        ].freeze

        DEFAULT_CONTEXT_CALLSITE = "Labkit::Context"

        # Placeholder logger_class used when an offense originates from the Labkit
        # context. The same context fields appear in every logger that runs within
        # the context, so collapsing across loggers prevents one offense per
        # logger x deprecated_field combination, and prevents new offenses being
        # raised whenever a developer adds a new logger class.
        ANY_LOGGER = "*"

        class << self
          def register_wrapper_pattern(pattern)
            wrapper_patterns << pattern
            @combined_ignore_pattern = nil
          end

          def wrapper_patterns
            @wrapper_patterns ||= LOGGER_WRAPPER_PATTERNS.dup
          end

          def reset_wrapper_patterns!
            @wrapper_patterns = nil
            @combined_ignore_pattern = nil
          end

          def combined_ignore_pattern
            @combined_ignore_pattern ||= Regexp.union(IGNORE_PATHS + wrapper_patterns)
          end

          # The callsite name used for offenses originating from the Labkit context
          # (e.g. ApplicationContext) rather than from the log caller directly.
          # Override this in your application to point to the actual context provider file:
          #   Labkit::Logging::FieldValidator::LogInterceptor.context_callsite =
          #     "lib/gitlab/application_context.rb"
          def context_callsite
            @context_callsite || DEFAULT_CONTEXT_CALLSITE
          end

          attr_writer :context_callsite

          def reset_context_callsite!
            @context_callsite = nil
          end

          # The context prefix that Labkit::Context applies to every field it
          # stores (see Labkit::Context::LOG_KEY). Any deprecated field with
          # this prefix is by convention a context field, owned by whichever
          # provider populates the context (e.g. ApplicationContext), even
          # when a particular log call happens to pass it directly. Lazily
          # built so the constant is not referenced at load time.
          def context_field_prefix
            @context_field_prefix ||= "#{::Labkit::Context::LOG_KEY}."
          end
        end

        def format_data(severity, timestamp, progname, message)
          data = super
          location = determine_callsite

          return data unless location

          callsite_path = normalize_path(location.path)
          return data unless callsite_path

          logger_class = self.class.name || 'AnonymousLogger'

          # Keys the caller explicitly passed in the log message. Any deprecated field
          # present in `data` but absent here arrived via Labkit::Context (e.g.
          # ApplicationContext) and should be attributed to the context callsite rather
          # than the individual log call site.
          direct_keys = message.is_a?(Hash) ? message.transform_keys(&:to_s).keys.to_set : Set.new
          context_prefix = LogInterceptor.context_field_prefix

          deprecated_lookup = Labkit::Fields::Deprecated.all
          if data.is_a?(Hash)
            data.each_key do |key|
              key_str = key.to_s
              standard_field = deprecated_lookup[key_str]
              next unless standard_field

              # context_prefix is the Labkit::Context namespace. The field is conceptually
              # context-owned even if the caller happens to pass it directly. Otherwise
              # use direct-vs-context based on whether the caller actually included it.
              if direct_keys.include?(key_str) && !key_str.start_with?(context_prefix)
                Registry.instance.record_offense(callsite_path, location.lineno, key_str, standard_field, logger_class)
              else
                Registry.instance.record_offense(LogInterceptor.context_callsite, 0, key_str, standard_field, ANY_LOGGER)
              end
            end
          end

          Registry.instance.check_for_removed_offenses(callsite_path, data, logger_class)
          Registry.instance.check_for_removed_offenses(LogInterceptor.context_callsite, data, ANY_LOGGER)

          data
        end

        private

        # Skip internal frames (determine_callsite, format_data, format_message, add, info) for performance.
        INTERNAL_FRAMES_TO_SKIP = 5
        MAX_FRAMES_TO_INSPECT = 15
        private_constant :INTERNAL_FRAMES_TO_SKIP, :MAX_FRAMES_TO_INSPECT

        def determine_callsite
          locations = caller_locations(INTERNAL_FRAMES_TO_SKIP, MAX_FRAMES_TO_INSPECT) || []
          locations = caller_locations(1, MAX_FRAMES_TO_INSPECT) || [] if locations.empty?
          ignore_pattern = LogInterceptor.combined_ignore_pattern

          locations.find do |loc|
            path = loc.path

            next if path == __FILE__
            next if ignore_pattern.match?(path)

            true
          end
        end

        def normalize_path(absolute_path)
          root = Config.root
          return nil unless absolute_path.start_with?(root)

          start_idx = root.length
          start_idx += 1 if absolute_path[start_idx] == '/'
          absolute_path[start_idx..]
        end
      end
    end
  end
end
