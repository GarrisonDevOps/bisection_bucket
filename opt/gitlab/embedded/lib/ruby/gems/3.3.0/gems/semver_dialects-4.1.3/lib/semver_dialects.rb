# frozen_string_literal: true

require 'semver_dialects/version'
require 'semver_dialects/base_version'
require 'semver_dialects/maven'
require 'semver_dialects/rpm'
require 'semver_dialects/apk'
require 'semver_dialects/semver2'
require 'semver_dialects/semantic_version'
require 'semver_dialects/boundary'
require 'semver_dialects/interval'
require 'semver_dialects/interval_parser'
require 'semver_dialects/interval_set'
require 'semver_dialects/interval_set_parser'
require 'deb_version'

module SemverDialects # rubocop:todo Style/Documentation
  # Captures all errors that could be possibly raised
  class Error < StandardError
  end

  class UnsupportedPackageTypeError < Error # rubocop:todo Style/Documentation
    def initialize(pkg_type)
      super
      @pkg_type = pkg_type
    end

    def message
      supported_types = SemverDialects.supported_package_types.join(', ')
      "unsupported package type '#{@pkg_type}'. Supported types are: #{supported_types}"
    end
  end

  class UnsupportedVersionError < Error # rubocop:todo Style/Documentation
    def initialize(raw_version)
      super
      @raw_version = raw_version
    end

    def message
      "unsupported version '#{@raw_version}'"
    end
  end

  class InvalidVersionError < Error # rubocop:todo Style/Documentation
    def initialize(raw_version)
      super
      @raw_version = raw_version
    end

    def message
      "invalid version '#{@raw_version}'"
    end
  end

  class InvalidConstraintError < Error # rubocop:todo Style/Documentation
    def initialize(raw_constraint)
      super
      @raw_constraint = raw_constraint
    end

    def message
      "invalid constraint '#{@raw_constraint}'"
    end
  end

  class IncompleteScanError < InvalidVersionError # rubocop:todo Style/Documentation
    attr_reader :rest

    def initialize(rest)
      super
      @rest = rest
    end

    def message
      "scan did not consume '#{@rest}'"
    end
  end

  # Determines if a version of a given package type satisfies a constraint.
  #
  # On normal execution, this method might raise the following exceptions:
  #
  # - UnsupportedPackageTypeError if the package type is not supported
  # - InvalidVersionError if the version is invalid
  # - InvalidConstraintError if the constraint is invalid or contains invalid versions
  #
  def self.version_satisfies?(typ, raw_ver, raw_constraint)
    # os package versions are handled very differently from application package versions
    return os_pkg_version_satisfies?(typ, raw_ver, raw_constraint) if os_purl_type?(typ)

    # build an interval that only contains the version
    version = SemverDialects.parse_version(typ, raw_ver)
    version_as_interval = Interval.from_version(version)

    interval_set = IntervalSetParser.parse(typ, raw_constraint)

    interval_set.overlaps_with?(version_as_interval)
  end

  def self.os_purl_type?(typ)
    %w[deb rpm apk].include?(typ)
  end

  def self.os_pkg_version_satisfies?(typ, raw_ver, raw_constraint)
    return unless %w[deb rpm apk].include?(typ)
    # we only support the less than operator, because that's the only one currently output
    # by the advisory exporter for operating system packages.
    raise SemverDialects::InvalidConstraintError, raw_constraint unless raw_constraint[0] == '<'

    v1 = SemverDialects.parse_version(typ, raw_ver)
    v2 = SemverDialects.parse_version(typ, raw_constraint[1..])

    v1 < v2
  end

  # Returns array of supported package types
  def self.supported_package_types
    %w[maven npm go pypi nuget gem packagist conan cargo apk deb rpm swift pub]
  end

  # Parse a version according to the syntax type.
  def self.parse_version(typ, raw_ver)
    raise InvalidVersionError, raw_ver if raw_ver.nil? || (raw_ver.respond_to?(:empty?) && raw_ver.empty?)

    # for efficiency most popular package types come first
    case typ
    when 'maven'
      Maven::VersionParser.parse(raw_ver)

    when 'npm'
      # npm follows Semver 2.0.0.
      Semver2::VersionParser.parse(cleanup(raw_ver))

    when 'go'
      # Go follows Semver 2.0.0.
      #
      # Go pseudo-versions are pre-releases as defined in Semver 2.0.0,
      # and can be compared as such. However, a pseudo-version can't be compared
      # to a pre-release or another pseudo-version of the same base version.
      #
      # quoting https://go.dev/ref/mod#pseudo-versions
      #
      # Each pseudo-version may be in one of three forms, depending on the base version.
      # These forms ensure that a pseudo-version compares higher than its base version,
      # but lower than the next tagged version.
      #

      # vX.0.0-yyyymmddhhmmss-abcdefabcdef is used when there is no known
      # base version. As with all versions, the major version X must match the
      # module’s major version suffix.
      #
      # vX.Y.Z-pre.0.yyyymmddhhmmss-abcdefabcdef is used when the base version
      # is a pre-release version like vX.Y.Z-pre.
      #
      # vX.Y.(Z+1)-0.yyyymmddhhmmss-abcdefabcdef is used when the base version
      # is a release version like vX.Y.Z. For example, if the base version is
      # v1.2.3, a pseudo-version might be v1.2.4-0.20191109021931-daa7c04131f5.
      #
      Semver2::VersionParser.parse(raw_ver)

    when 'pypi'
      # See https://packaging.python.org/en/latest/specifications/version-specifiers/#version-specifiers
      # TODO: Implement a dedicated parser.
      SemanticVersion.new(raw_ver)

    when 'nuget'
      # NuGet diverges from Semver 2.0.0.
      #
      # quoting https://learn.microsoft.com/en-us/nuget/concepts/package-versioning#where-nugetversion-diverges-from-semantic-versioning
      #
      # NuGetVersion supports a 4th version segment, Revision, to be compatible
      # with, or a superset of, System.Version. Therefore, excluding prerelease
      # and metadata labels, a version string is Major.Minor.Patch.Revision. As
      # per version normalization described above, if Revision is zero, it is
      # omitted from the normalized version string.
      #
      # NuGetVersion only requires the major segment to be defined. All others
      # are optional, and are equivalent to zero. This means that 1, 1.0,
      # 1.0.0, and 1.0.0.0 are all accepted and equal.
      #
      # NuGetVersion uses case insensitive string comparisons for pre-release
      # components. This means that 1.0.0-alpha and 1.0.0-Alpha are equal.
      #
      Semver2::VersionParser.parse(raw_ver.downcase)

    when 'gem'
      # Rubygem does not follow Semver. Its versioning scheme is not documented.
      #
      # quoting https://guides.rubygems.org/specification-reference/
      #
      # The version string can contain numbers and periods, such as 1.0.0. A
      # gem is a ‘prerelease’ gem if the version has a letter in it, such as
      # 1.0.0.pre.
      Gem::Version.new(raw_ver)

    when 'packagist'
      # Packagist defines specific identifiers like alpha, beta, and stable,
      # and the comparison rules for these are not compatible with Semver.
      # See https://github.com/composer/semver/blob/1d09200268e7d1052ded8e5da9c73c96a63d18f5/src/VersionParser.php#L39
      SemanticVersion.new(raw_ver)

    when 'conan'
      # Conan diverges from Semver 2.0.0.
      #
      # quoting https://docs.conan.io/2/tutorial/versioning/version_ranges.html#semantic-versioning
      #
      # Conan extends the semver specification to any number of digits, and
      # also allows to include lowercase letters in it. This was done because
      # during 1.X a lot of experience and feedback from users was gathered,
      # and it became evident than in C++ the versioning scheme is often more
      # complex, and users were demanding more flexibility, allowing versions
      # like 1.2.3.a.8 if necessary.
      #
      # Conan versions non-digit identifiers follow the same rules as package
      # names, they can only contain lowercase letters. This is to avoid
      # 1.2.3-Beta to be a different version than 1.2.3-beta which can be
      # problematic, even a security risk.
      #
      SemanticVersion.new(raw_ver)

    when 'cargo'
      # cargo follows Semver 2.0.0.
      Semver2::VersionParser.parse(raw_ver)

    when 'swift'
      # swift follows Semver 2.0.0.
      Semver2::VersionParser.parse(raw_ver)

    when 'pub'
      # pub follows Semver 2.0.0.
      Semver2::VersionParser.parse(raw_ver)

    when 'apk'
      Apk::VersionParser.parse(raw_ver)
    when 'deb'
      DebVersion.new(raw_ver)
    when 'rpm'
      Rpm::VersionParser.parse(raw_ver)
    else
      raise UnsupportedPackageTypeError, typ
    end
  rescue ArgumentError, TypeError, NoMethodError
    raise InvalidVersionError, raw_ver
  end

  # cleanup loose npm versions
  def self.cleanup(raw_ver)
    raw_ver.strip.gsub(/^[=v]/, '')
  end
end
