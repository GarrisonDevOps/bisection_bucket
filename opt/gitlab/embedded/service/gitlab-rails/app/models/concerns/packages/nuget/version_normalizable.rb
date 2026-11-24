# frozen_string_literal: true

module Packages
  module Nuget
    module VersionNormalizable
      extend ActiveSupport::Concern

      LEADING_ZEROES_REGEX = /^(?!0$)0+(?=\d)/

      included do
        before_validation :set_normalized_version, on: %i[create update]

        private

        def set_normalized_version
          return unless package

          self.normalized_version = self.class.normalize_version(package_version)
        end
      end

      class_methods do
        def normalize_version(version)
          version = remove_leading_zeroes(version)
          version = remove_build_metadata(version)
          version = omit_zero_in_fourth_part(version)
          append_suffix(version)
        end

        # A prerelease label can hold dots and leading zeros that normalize_version would
        # treat as version parts, so a lookup normalizes only a release version.
        def release_version?(version)
          match = Gitlab::Regex.nuget_version_regex.match(version)

          match.present? && match[:prerelease].nil?
        end

        # NuGet clients request a release by its normalized version.
        def normalized_release_version?(version)
          release_version?(version) && normalize_version(version) == version.downcase
        end

        def normalized_lookup_version(version)
          release_version?(version) ? normalize_version(version) : version.to_s.downcase
        end

        private

        def remove_leading_zeroes(version)
          version.split('.').map { |part| part.sub(LEADING_ZEROES_REGEX, '') }.join('.')
        end

        def remove_build_metadata(version)
          version.split('+').first.downcase
        end

        def omit_zero_in_fourth_part(version)
          parts = version.split('.')
          parts[3] = nil if parts.fourth == '0' && parts.third.exclude?('-')
          parts.compact.join('.')
        end

        def append_suffix(version)
          version << '.0.0' if version.count('.') == 0
          version << '.0' if version.count('.') == 1
          version
        end
      end
    end
  end
end
