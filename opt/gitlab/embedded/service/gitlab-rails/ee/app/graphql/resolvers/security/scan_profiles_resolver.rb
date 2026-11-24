# frozen_string_literal: true

module Resolvers
  module Security
    class ScanProfilesResolver < BaseResolver
      include Gitlab::Graphql::Authorize::AuthorizeResource

      type [Types::Security::ScanProfileType], null: false
      authorize :read_security_scan_profiles
      description 'Available security scan profiles.'

      argument :type, Types::Security::ScanProfileTypeEnum,
        required: false,
        description: 'Filter scan profiles by type.'

      argument :gitlab_recommended, GraphQL::Types::Boolean,
        required: false,
        description: 'Filter scan profiles by GitLab Recommended.'

      alias_method :group, :object

      def resolve(type: nil, gitlab_recommended: nil)
        authorize!(object)

        existing_profiles = fetch_existing_profiles(type, gitlab_recommended)
        applicable_defaults = fetch_applicable_defaults(type, existing_profiles, gitlab_recommended)

        # Sort after concatenating: an unpersisted recommended profile only exists in the defaults,
        # so ordering the query alone would still leave it last. Name breaks ties because sort_by
        # is unstable and the defaults have no id yet.
        (existing_profiles + applicable_defaults)
          .sort_by { |profile| [profile.gitlab_recommended ? 0 : 1, profile.name] }
      end

      private

      def root_ancestor
        @root_ancestor ||= group.root_ancestor
      end

      def fetch_existing_profiles(type, gitlab_recommended)
        # Eager-load trigger configurations to avoid N+1s when resolving ScanProfileType#configuration.
        profiles = ::Security::ScanProfile.not_deleted.by_namespace(root_ancestor).with_trigger_configurations
        # Hide saved Business Logic profiles while the flag is off, like the preset below.
        profiles = profiles.not_business_logic unless business_logic_enabled?
        profiles = profiles.not_skillguard unless skillguard_enabled?
        profiles = filter_by_type(profiles, type)
        filter_by_gitlab_recommended(profiles, gitlab_recommended)
      end

      def filter_by_type(profiles, type)
        return profiles if type.blank?

        profiles.by_type(type)
      end

      def filter_by_gitlab_recommended(profiles, gitlab_recommended)
        return profiles if gitlab_recommended.nil?

        profiles.by_gitlab_recommended(gitlab_recommended)
      end

      def fetch_applicable_defaults(type, existing_profiles, gitlab_recommended)
        return [] if gitlab_recommended == false

        persisted_keys = existing_profiles.select(&:gitlab_recommended).map { |profile| profile_key(profile) }.to_set

        default_scan_profiles
          .select { |profile| matches_requested_type?(profile, type) }
          .reject { |profile| persisted_keys.include?(profile_key(profile)) }
      end

      # Name is part of the key because a single scan type can have several default presets.
      # Gotcha: renaming a default in the helper stops it deduping against rows persisted under the old name.
      def profile_key(profile)
        [profile.scan_type, profile.name]
      end

      def matches_requested_type?(profile, type)
        type.blank? || profile.scan_type == type
      end

      def default_scan_profiles
        @default_scan_profiles ||= ::Security::DefaultScanProfilesHelper.default_scan_profiles
          .reject { |scan_profile| scan_profile.triage_and_remediation? && !triage_and_remediation_enabled? }
          .reject { |scan_profile| scan_profile.business_logic? && !business_logic_enabled? }
          .reject { |scan_profile| scan_profile.skillguard? && !skillguard_enabled? }
          .each { |scan_profile| scan_profile.namespace_id = root_ancestor.id }
      end

      def triage_and_remediation_enabled?
        Feature.enabled?(:triage_and_remediation_profile, root_ancestor)
      end

      def business_logic_enabled?
        ::Ai::Catalog::FoundationalFlow::BlSecurity::Definition.scan_profiles_enabled_for?(root_ancestor)
      end

      def skillguard_enabled?
        Feature.enabled?(:skillguard_analyzer, root_ancestor)
      end
    end
  end
end
