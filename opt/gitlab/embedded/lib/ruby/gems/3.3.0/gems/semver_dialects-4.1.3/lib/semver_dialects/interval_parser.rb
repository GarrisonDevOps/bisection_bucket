# frozen_string_literal: true

# IntervalParser parses a simple constraint expressed in the npm syntax
# (or equivalent) and returns a Interval that has an upper boundary
# or a lower boundary.
#
# The constraint is a string that can either be:
# - an operator (>, <, >=, <=, =) followed by a version
# - a version; the interval starts and ends with that version
# - "=*"; the interval has no boundaries and includes any version
#
# Technically IntervalParser returns a Interval such as
# start_cut is BelowAll or end_cut is AboveAll.
# The type of the Interval matches the operator
# that's been detected.
#
module SemverDialects
  module IntervalParser # rubocop:todo Style/Documentation
    # Version string validation is only validated not to be white space.
    # All other version validation is delegated to the version parsers.
    CONSTRAINT_REGEXP = Regexp.new('(?<op>[><=]+)\s*(?<version>[^\s]+)').freeze

    def self.parse(typ, versionstring)
      if versionstring == '=*'
        # special case = All Versions
        return Interval.new(IntervalType::LEFT_OPEN | IntervalType::RIGHT_OPEN, BelowAll.new, AboveAll.new)
      end

      version_items = versionstring.split(' ')
      interval = Interval.new(IntervalType::LEFT_OPEN | IntervalType::RIGHT_OPEN, BelowAll.new, AboveAll.new)
      version_items.each do |version_item|
        matches = version_item.match CONSTRAINT_REGEXP
        raise InvalidConstraintError, versionstring if matches.nil?

        version = SemverDialects.parse_version(typ, matches[:version])
        boundary = Boundary.new(version)
        case matches[:op]
        when '>='
          new_interval = Interval.new(IntervalType::LEFT_CLOSED | IntervalType::RIGHT_OPEN, boundary, AboveAll.new)
          interval = interval.intersect(new_interval)
        when '<='
          new_interval = Interval.new(IntervalType::LEFT_OPEN | IntervalType::RIGHT_CLOSED, BelowAll.new, boundary)
          interval = interval.intersect(new_interval)
        when '<'
          new_interval = Interval.new(IntervalType::LEFT_OPEN | IntervalType::RIGHT_OPEN, BelowAll.new, boundary)
          interval = interval.intersect(new_interval)
        when '>'
          new_interval = Interval.new(IntervalType::LEFT_OPEN | IntervalType::RIGHT_OPEN, boundary, AboveAll.new)
          interval = interval.intersect(new_interval)
        when '=', '=='
          new_interval = Interval.new(IntervalType::LEFT_CLOSED | IntervalType::RIGHT_CLOSED, boundary, boundary)
          interval = interval.intersect(new_interval)
        end
      end
      interval
    rescue InvalidVersionError
      raise InvalidConstraintError, versionstring
    end
  end
end
