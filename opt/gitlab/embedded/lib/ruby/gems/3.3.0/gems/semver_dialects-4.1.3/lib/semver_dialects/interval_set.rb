# frozen_string_literal: true

# IntervalSet is a disjunction of version intervals.
# It can express a range like "[1.0,2.0],[3.0,4.0]" (Maven syntax),
# that is between 1.0 and 2.0 (included) OR between 3.0 and 4.0 (included).
module SemverDialects
  class IntervalSet # rubocop:todo Style/Documentation
    attr_reader :intervals

    def initialize
      @intervals = []
    end

    def add(interval)
      @intervals << interval
    end

    def <<(item)
      add(item)
    end

    def size
      @intervals.size
    end

    def to_s
      @intervals.map(&:to_s).join(',')
    end

    def to_description_s
      @intervals.map(&:to_description_s).join(', ').capitalize
    end

    def to_npm_s
      @intervals.map(&:to_npm_s).join('||')
    end

    def to_conan_s
      to_npm_s
    end

    def to_nuget_s
      to_maven_s
    end

    def to_maven_s
      @intervals.map(&:to_maven_s).join(',')
    end

    def to_gem_s
      @intervals.map(&:to_gem_s).join('||')
    end

    def to_pypi_s
      @intervals.map(&:to_pypi_s).join('||')
    end

    def to_go_s
      @intervals.map(&:to_go_s).join('||')
    end

    def to_packagist_s
      @intervals.map(&:to_packagist_s).join('||')
    end

    def to_cargo_s
      to_npm_s
    end

    def to_swift_s
      to_npm_s
    end

    def to_pub_s
      to_npm_s
    end

    def to_version_s(package_type)
      case package_type
      when 'npm'
        to_npm_s
      when 'nuget'
        to_nuget_s
      when 'maven'
        to_maven_s
      when 'gem'
        to_gem_s
      when 'pypi'
        to_pypi_s
      when 'packagist'
        to_packagist_s
      when 'go'
        to_go_s
      when 'conan'
        to_conan_s
      else
        ''
      end
    end

    def includes?(other)
      @intervals.include?(other)
    end

    def overlaps_with?(other)
      @intervals.each do |interval|
        return true unless interval.intersect(other).instance_of?(EmptyInterval)
      end
      false
    end

    def first
      @intervals.first
    end

    def empty?
      @intervals.empty?
    end

    def any?
      @intervals.any?
    end

    def universal?
      @intervals.each do |interval|
        return true if interval.universal?
      end
      false
    end
  end
end
