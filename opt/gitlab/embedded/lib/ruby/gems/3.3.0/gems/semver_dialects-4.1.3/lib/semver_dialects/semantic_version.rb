# frozen_string_literal: true

require_relative '../utils'

module SemverDialects
  # SemanticVersion is a generic version class.
  # It parses and compares versions of any syntax.
  # It can't always be accurate because a single comparison logic
  # can't possibly handle all the supported syntaxes.
  # Since it's generic, it doesn't validate versions.
  class SemanticVersion
    include Comparable

    ANY_NUMBER = 'x'

    attr_reader :version_string, :prefix_segments, :suffix_segments, :segments

    # String to build a regexp that matches a version.
    #
    # A version might start with a leading "v", then it must have a digit,
    # then it might have any sequence made of alphanumerical characters,
    # underscores, dots, dashes, and wildcards.
    VERSION_PATTERN = 'v?[0-9][a-zA-Z0-9_.*+-]*'

    # Regexp for a string that only contains a single version string.
    VERSION_ONLY_REGEXP = Regexp.new("\\A#{VERSION_PATTERN}\\z").freeze

    def initialize(version_string)
      raise InvalidVersionError, version_string unless VERSION_ONLY_REGEXP.match version_string

      @version_string = version_string
      @prefix_segments = []
      @suffix_segments = []
      version, = version_string.delete_prefix('v').split('+')
      @segments = split_version_string!(version)
    end

    def split_version_string!(version_string)
      delim_pattern = /[.-]/
      split_array = version_string.split(delim_pattern).map do |grp|
        grp.split(/(\d+)/).reject { |cell| cell.nil? || cell.empty? }
      end.flatten

      # go as far to the right as possible considering numbers and placeholders
      prefix_delimiter = 0
      (0..split_array.size - 1).each do |i|
        break unless split_array[i].number? || split_array[i] == 'X' || split_array[i] == 'x'

        prefix_delimiter = i
      end

      # remove redundant trailing zeros
      prefix_delimiter.downto(0).each do |i|
        break unless split_array[i] == '0'

        split_array.delete_at(i)
        prefix_delimiter -= 1
      end

      unless prefix_delimiter.negative?
        @prefix_segments = split_array[0..prefix_delimiter].map do |group_string|
          SemanticVersionSegment.new(group_string)
        end
      end
      if split_array.size - 1 >= prefix_delimiter + 1
        @suffix_segments = split_array[prefix_delimiter + 1, split_array.size].map do |group_string|
          SemanticVersionSegment.new(group_string)
        end
      end

      @prefix_segments.clone.concat(@suffix_segments)
    end

    def _get_equalized_arrays_for(array_a, array_b)
      first_array = array_a.clone
      second_array = array_b.clone
      if first_array.size < second_array.size
        (second_array.size - first_array.size).times do
          first_array << SemanticVersionSegment.new('0')
        end
      elsif first_array.size > second_array.size
        (first_array.size - second_array.size).times do
          second_array << SemanticVersionSegment.new('0')
        end
      end
      [first_array, second_array]
    end

    def get_equalized_arrays_for(semver_a, semver_b)
      first_array_prefix = semver_a.prefix_segments.clone
      second_array_prefix = semver_b.prefix_segments.clone
      first_array_suffix = semver_a.suffix_segments.clone
      second_array_suffix = semver_b.suffix_segments.clone
      first_array_prefix, second_array_prefix = _get_equalized_arrays_for(first_array_prefix, second_array_prefix)
      first_array_suffix, second_array_suffix = _get_equalized_arrays_for(first_array_suffix, second_array_suffix)
      [first_array_prefix.concat(first_array_suffix), second_array_prefix.concat(second_array_suffix)]
    end

    def is_zero? # rubocop:todo Naming/PredicateName
      @prefix_segments.empty? || @prefix_segments.all?(&:is_zero?)
    end

    def pre_release?
      @suffix_segments.any?(&:is_pre_release)
    end

    def post_release?
      @suffix_segments.any?(&:is_post_release)
    end

    WILDCARD_HIT = :__wildcard_hit__

    def <=>(other)
      return nil unless other.is_a?(SemanticVersion)

      cmp = compare_segments(@prefix_segments, other.prefix_segments)
      return 0 if cmp.equal?(WILDCARD_HIT)
      return cmp unless cmp.zero?

      cmp = compare_segments(@suffix_segments, other.suffix_segments)
      return 0 if cmp.equal?(WILDCARD_HIT)

      cmp
    end

    def to_normalized_s
      @segments.map(&:to_normalized_s).join(':')
    end

    def to_s
      @version_string
    end

    def major
      @prefix_segments.size >= 1 ? @prefix_segments[0].to_s : '0'
    end

    def minor
      @prefix_segments.size >= 2 ? @prefix_segments[1].to_s : '0'
    end

    def patch
      @prefix_segments.size >= 3 ? @prefix_segments[2].to_s : '0'
    end

    private

    def compare_segments(a, b) # rubocop:disable Naming/MethodParameterName
      zero = SemverDialects::ZERO_SEGMENT
      len = a.size > b.size ? a.size : b.size
      i = 0
      while i < len
        seg_a = i < a.size ? a[i] : zero
        seg_b = i < b.size ? b[i] : zero
        return WILDCARD_HIT if seg_a.wildcard? || seg_b.wildcard?

        cmp = seg_a <=> seg_b
        return cmp if cmp != 0

        i += 1
      end
      0
    end
  end

  class SemanticVersionSegment # rubocop:todo Style/Documentation
    include Comparable

    attr_accessor :normalized_group_string, :original_group_string, :is_post_release, :is_pre_release

    @@group_suffixes = { # rubocop:todo Style/ClassVars
      # pre-releases
      'PRE' => -16,
      'PREVIEW' => -16,
      'DEV' => -15,
      'A' => -14,
      'ALPHA' => -13,
      'B' => -12,
      'BETA' => -12,
      'RC' => -11,
      'M' => -10,

      'RELEASE' => 0,
      'FINAL' => 0,
      # PHP specific
      'STABLE' => 0,

      # post-releases
      'SP' => 1
    }

    def initialize(group_string)
      @is_post_release = false
      @is_pre_release = false

      @version_string = group_string
      @original_group_string = group_string
      # use x as unique placeholder
      group_string_ucase = group_string.to_s.gsub(/\*/, 'x').upcase

      if @@group_suffixes.key?(group_string_ucase)
        value = @@group_suffixes[group_string_ucase]
        @is_post_release = value.positive?
        @is_pre_release = value.negative?
        @normalized_group_string = @@group_suffixes[group_string_ucase].to_s
      else
        @normalized_group_string = group_string_ucase
      end

      parsed = Integer(@normalized_group_string, exception: false)
      @numeric_value = parsed
      @is_numeric = !parsed.nil?
      @is_wildcard = @normalized_group_string == 'X'
    end

    def <=>(other)
      return nil unless other.is_a?(SemanticVersionSegment)

      return 0 if @is_wildcard || other.wildcard?

      if @is_numeric
        return @numeric_value <=> other.numeric_value if other.numeric?

        -1
      elsif other.numeric?
        1
      else
        @normalized_group_string <=> other.normalized_group_string
      end
    end

    attr_reader :numeric_value

    def numeric?
      @is_numeric
    end

    def to_normalized_s
      @normalized_group_string
    end

    def to_s
      @version_string
    end

    def wildcard?
      @is_wildcard
    end

    def is_number? # rubocop:todo Naming/PredicateName
      @is_numeric
    end

    def is_zero? # rubocop:todo Naming/PredicateName
      @is_numeric && @numeric_value.zero?
    end
  end

  ZERO_SEGMENT = SemanticVersionSegment.new('0').freeze
end
