# frozen_string_literal: true

# Boundary is a boundary used in an interval.
# It can either be above all versions (infinity),
# below all versions (negative infinity), or any version.
module SemverDialects
  class Boundary # rubocop:todo Style/Documentation
    include Comparable

    attr_accessor :semver

    def initialize(semver)
      @semver = semver
    end

    def to_s
      @semver.to_s
    end

    def <=>(other)
      return nil unless other.is_a?(Boundary)
      return -1 if other.instance_of?(AboveAll)
      return 1 if other.instance_of?(BelowAll)

      semver <=> other.semver
    end

    def is_initial_version? # rubocop:todo Naming/PredicateName
      @semver.is_zero?
    end
  end

  # BelowAll represents a boundary below all possible versions.
  # When used as the lower boundary of an interval, any version
  # that is smaller than the upper boundary is in the interval.
  class BelowAll < Boundary
    def initialize; end # rubocop:todo Lint/MissingSuper

    def to_s
      '-inf'
    end

    def is_initial_version? # rubocop:todo Naming/PredicateName
      false
    end

    def <=>(other)
      return 0 if other.instance_of?(BelowAll)

      -1 if other.is_a?(Boundary)
    end
  end

  # AboveAll represents a boundary above all possible versions.
  # When used as the upper boundary of an interval, any version
  # that is greater than the lower boundary is in the interval.
  class AboveAll < Boundary
    def initialize; end # rubocop:todo Lint/MissingSuper

    def to_s
      '+inf'
    end

    def is_initial_version? # rubocop:todo Naming/PredicateName
      false
    end

    def <=>(other)
      return 0 if other.instance_of?(AboveAll)

      1 if other.is_a?(Boundary)
    end
  end
end
