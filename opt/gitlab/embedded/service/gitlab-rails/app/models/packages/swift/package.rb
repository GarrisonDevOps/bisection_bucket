# frozen_string_literal: true

module Packages
  module Swift
    class Package < Packages::Package
      self.allow_legacy_sti_class = true

      validates :name, format: {
        with: Gitlab::Regex.swift_package_identifier_regex,
        message: 'must be a Swift package identifier in the form scope.name'
      }

      validates :version, format: {
        with: Gitlab::Regex.semver_regex,
        message: Gitlab::Regex.semver_regex_message
      }

      # Scopes and names are case-insensitive per the registry specification, so the
      # identifier is matched without regard to the case it was published under.
      scope :with_identifier, ->(scope_name, package_name) do
        with_case_insensitive_name("#{scope_name}.#{package_name}")
      end
    end
  end
end
