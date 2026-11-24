# frozen_string_literal: true

module Gitlab
  module Duo
    module CodeReview
      class CustomInstruction
        include Gitlab::Utils::StrongMemoize

        attr_reader :name, :instructions, :include_patterns, :exclude_patterns, :location

        def initialize(name:, instructions:, include_patterns:, exclude_patterns:, location:)
          @name = name
          @instructions = instructions
          @include_patterns = include_patterns
          @exclude_patterns = exclude_patterns
          @location = location
        end

        def valid?
          name.present? && instructions.present?
        end

        def apply_to?(path)
          # Matching logic:
          # - With include patterns: Match ONLY files that match include patterns (minus exclusions)
          # - Without include patterns: Match ALL files (minus exclusions)
          matches_include?(path) && !matches_exclude?(path)
        end

        # Required for backward compatibility with existing code (e.g., ReviewMergeRequest) that expects hash-like
        # access. Will be removed once all consumers are updated to use the CustomInstruction interface.
        def [](key)
          to_h[key]
        end

        def to_h
          {
            name: name,
            instructions: instructions,
            include_patterns: include_patterns,
            exclude_patterns: exclude_patterns,
            location: location
          }.with_indifferent_access
        end
        strong_memoize_attr :to_h

        private

        def matches_include?(path)
          return true if include_patterns.empty?

          match_any?(include_patterns, path)
        end

        def matches_exclude?(path)
          match_any?(exclude_patterns, path)
        end

        def match_any?(patterns, path)
          patterns.any? do |pattern|
            File.fnmatch?(pattern, path, File::FNM_PATHNAME | File::FNM_EXTGLOB)
          end
        end
      end
    end
  end
end
