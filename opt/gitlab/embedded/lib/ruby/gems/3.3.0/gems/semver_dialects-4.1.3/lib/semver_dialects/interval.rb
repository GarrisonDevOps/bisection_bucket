# frozen_string_literal: true

module SemverDialects
  module IntervalType
    UNKNOWN = 0
    LEFT_OPEN = 1
    LEFT_CLOSED = 2
    RIGHT_OPEN = 4
    RIGHT_CLOSED = 8
  end

  # Interval is an interval that starts with a lower boundary
  # and ends with an upper boundary. The interval includes the boundaries
  # or not depending on its type.
  class Interval
    # Returns an interval that only includes the given version.
    def self.from_version(version)
      boundary = Boundary.new(version)
      Interval.new(IntervalType::LEFT_CLOSED | IntervalType::RIGHT_CLOSED, boundary, boundary)
    end

    attr_accessor :type, :start_cut, :end_cut

    def initialize(type, start_cut, end_cut)
      @type = type
      @start_cut = start_cut
      @end_cut = end_cut
    end

    def intersect(other_interval)
      return EmptyInterval.new if empty?

      # this look odd -- we have to use it here though, because it may be that placeholders are present inside
      # the version for which > and < would yield true
      return EmptyInterval.new if @start_cut > other_interval.end_cut || other_interval.start_cut > @end_cut

      start_cut_new = max(@start_cut, other_interval.start_cut)
      end_cut_new = min(@end_cut, other_interval.end_cut)

      # compute the boundaries for the intersection
      type = compute_intersection_boundary(self, other_interval, start_cut_new, end_cut_new)
      interval = Interval.new(type, start_cut_new, end_cut_new)
      half_open = !(interval.bit_set?(IntervalType::RIGHT_CLOSED) && interval.bit_set?(IntervalType::LEFT_CLOSED))

      interval.singleton? && half_open ? EmptyInterval.new : interval
    end

    def special(cut)
      cut.instance_of?(AboveAll) || cut.instance_of?(BelowAll)
    end

    def to_s
      s = ''
      s += bit_set?(IntervalType::LEFT_CLOSED) ? '[' : ''
      s += bit_set?(IntervalType::LEFT_OPEN) ? '(' : ''
      s += [@start_cut, @end_cut].join(',')
      s += bit_set?(IntervalType::RIGHT_CLOSED) ? ']' : ''
      s += bit_set?(IntervalType::RIGHT_OPEN) ? ')' : ''
      s
    end

    # this function returns a human-readable descriptions of the version strings
    def to_description_s
      s = ''
      if distinct?
        s = "version #{@start_cut}"
      elsif universal?
        s = 'all versions '
      else
        s = 'all versions '
        s += if start_cut.instance_of?(BelowAll)
               ''
             elsif bit_set?(IntervalType::LEFT_OPEN)
               "after #{@start_cut} "
             else
               bit_set?(IntervalType::LEFT_CLOSED) ? "starting from #{@start_cut} " : ''
             end
        s += if end_cut.instance_of?(AboveAll)
               ''
             elsif bit_set?(IntervalType::RIGHT_OPEN)
               "before #{@end_cut}"
             else
               bit_set?(IntervalType::RIGHT_CLOSED) ? "up to #{@end_cut}" : ''
             end
      end
      s.strip
    end

    def to_nuget_s
      to_maven_s
    end

    def to_maven_s
      s = ''
      # special case -- distinct version
      if distinct?
        s += "[#{@start_cut}]"
      else
        s += if start_cut.instance_of?(BelowAll)
               '(,'
             elsif bit_set?(IntervalType::LEFT_OPEN)
               "[#{@start_cut},"
             else
               bit_set?(IntervalType::LEFT_CLOSED) ? "[#{@start_cut}," : ''
             end
        s += if end_cut.instance_of?(AboveAll)
               ')'
             elsif bit_set?(IntervalType::RIGHT_OPEN)
               "#{@end_cut})"
             else
               bit_set?(IntervalType::RIGHT_CLOSED) ? "#{@end_cut}]" : ''
             end
      end
      s
    end

    def distinct?
      bit_set?(IntervalType::LEFT_CLOSED) && bit_set?(IntervalType::RIGHT_CLOSED) && @start_cut == @end_cut
    end

    def subsumes?(other)
      @start_cut <= other.start_cut && @end_cut >= other.end_cut
    end

    def universal?
      (bit_set?(IntervalType::LEFT_OPEN) && bit_set?(IntervalType::RIGHT_OPEN) &&
        @start_cut.instance_of?(BelowAll) && @end_cut.instance_of?(AboveAll)) ||
        @start_cut.is_initial_version? && @end_cut.instance_of?(AboveAll)
    end

    def to_gem_s
      get_canoncial_s
    end

    def to_ruby_s
      get_canoncial_s
    end

    def to_npm_s
      get_canoncial_s
    end

    def to_conan_s
      get_canoncial_s
    end

    def to_go_s
      get_canoncial_s
    end

    def to_pypi_s
      get_canoncial_s(',', '==')
    end

    def to_packagist_s
      get_canoncial_s(',')
    end

    def to_cargo_s
      get_canoncial_s
    end

    def to_swift_s
      get_canoncial_s
    end

    def to_pub_s
      get_canoncial_s
    end

    def empty?
      instance_of?(EmptyInterval)
    end

    def singleton?
      @start_cut == @end_cut && @start_cut.semver == @end_cut.semver
    end

    def ==(other)
      @start_cut == other.start_cut && @end_cut == other.end_cut && @type == other.type
    end

    def bit_set?(interval_type)
      @type & interval_type != 0
    end

    protected

    def compute_intersection_boundary(interval_a, interval_b, start_cut_new, end_cut_new)
      compute_boundary(interval_a, interval_b, start_cut_new, end_cut_new, IntervalType::LEFT_OPEN,
                       IntervalType::RIGHT_OPEN)
    end

    def compute_boundary(interval_a, interval_b, start_cut_new, end_cut_new, left_check, right_check) # rubocop:disable Metrics/ParameterLists
      start_cut_a = interval_a.start_cut
      end_cut_a = interval_a.end_cut
      type_a = interval_a.type

      start_cut_b = interval_b.start_cut
      end_cut_b = interval_b.end_cut
      type_b = interval_b.type

      left_fill = left_check == IntervalType::LEFT_OPEN ? IntervalType::LEFT_CLOSED : IntervalType::LEFT_OPEN
      right_fill = right_check == IntervalType::RIGHT_OPEN ? IntervalType::RIGHT_CLOSED : IntervalType::RIGHT_OPEN

      # compute the boundaries for the union
      if start_cut_b == start_cut_a
        one_left_closed = left_type(type_a) == left_check || left_type(type_b) == left_check
        left_type = one_left_closed ? left_check : left_fill
      else
        left_type = start_cut_new == start_cut_a ? left_type(type_a) : left_type(type_b)
      end

      if end_cut_b == end_cut_a
        one_right_closed = right_type(type_a) == right_check || right_type(type_b) == right_check
        right_type = one_right_closed ? right_check : right_fill
      else
        right_type = end_cut_new == end_cut_a ? right_type(type_a) : right_type(type_b)
      end

      left_type | right_type
    end

    def get_canoncial_s(delimiter = ' ', eq = '=') # rubocop:todo Naming/MethodParameterName
      if distinct?
        "#{eq}#{@start_cut}"
      else
        first = if start_cut.instance_of?(BelowAll)
                  ''
                elsif bit_set?(IntervalType::LEFT_OPEN)
                  ">#{@start_cut}"
                else
                  bit_set?(IntervalType::LEFT_CLOSED) ? ">=#{@start_cut}" : ''
                end
        second = if end_cut.instance_of?(AboveAll)
                   ''
                 elsif bit_set?(IntervalType::RIGHT_OPEN)
                   "<#{@end_cut}"
                 else
                   bit_set?(IntervalType::RIGHT_CLOSED) ? "<=#{@end_cut}" : ''
                 end
        !first.empty? && !second.empty? ? "#{first}#{delimiter}#{second}" : first + second
      end
    end

    def max(cut_a, cut_b)
      cut_a > cut_b ? cut_a : cut_b
    end

    def min(cut_a, cut_b)
      cut_a < cut_b ? cut_a : cut_b
    end

    def right_type(type)
      (IntervalType::RIGHT_OPEN | IntervalType::RIGHT_CLOSED) & type
    end

    def left_type(type)
      (IntervalType::LEFT_OPEN | IntervalType::LEFT_CLOSED) & type
    end
  end

  class EmptyInterval < Interval # rubocop:todo Style/Documentation
    def initialize; end # rubocop:todo Lint/MissingSuper

    def to_s
      'empty'
    end
  end
end
