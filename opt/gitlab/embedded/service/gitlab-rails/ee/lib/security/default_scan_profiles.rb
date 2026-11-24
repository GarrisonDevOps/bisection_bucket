# frozen_string_literal: true

module Security
  class DefaultScanProfiles
    def self.all
      Security::DefaultScanProfilesHelper.default_scan_profiles
    end

    def self.find_by_scan_type(scan_type)
      all.find { |profile| profile.scan_type == scan_type.to_s }
    end

    def self.find_by_preset_key(preset_key)
      return if preset_key.blank?

      all.find { |profile| profile.preset_key == preset_key.to_s }
    end

    def self.virtual_identifier?(identifier)
      return false if identifier.blank?

      Enums::Security.security_profile_types.key?(identifier.to_sym) || find_by_preset_key(identifier).present?
    end

    def self.reserved_name?(name)
      return false if name.blank?

      all.any? { |profile| profile.name.casecmp?(name) }
    end
  end
end
