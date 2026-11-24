# frozen_string_literal: true

module Security
  # Applies license overrides from active approval policies to license data.
  # Used by SBOM export services and the Dependency List to ensure overridden
  # licenses appear in all output formats (CycloneDX, JSON, CSV).
  #
  # Operates on license hashes (from sbom_occurrences.licenses JSONB) -- does NOT
  # mutate the original data. Returns a new array of license hashes.
  class LicenseOverrideApplicator
    include Gitlab::Utils::StrongMemoize
    include Security::LicenseOverrides::Shared

    UNKNOWN_SPDX = 'unknown'

    # Null object that does nothing -- avoids nil checks in callers.
    NullApplicator = Class.new do
      def overrides?
        false
      end

      def apply(licenses, purl: nil) # rubocop:disable Lint/UnusedMethodArgument -- null object
        licenses
      end
    end

    NULL_APPLICATOR = NullApplicator.new.freeze

    EXPERIMENT_NAME = :license_overrides

    # Maximum number of override entries to aggregate for a group.
    # Prevents unbounded memory growth for groups with many projects/policies.
    MAX_GROUP_OVERRIDES = 1_000

    # Returns true if the group's security orchestration policy configuration
    # has the experiment enabled.
    def self.experiment_enabled_for_group?(group)
      return false unless group

      config = group.security_orchestration_policy_configuration
      return false unless config

      config.experiment_enabled?(EXPERIMENT_NAME)
    end

    # Returns true if ANY security orchestration policy configuration linked to
    # the project (direct or inherited from namespace) has the experiment enabled.
    def self.experiment_enabled_for_project?(project)
      return false unless project

      project.all_security_orchestration_policy_configurations.any? do |config|
        config.experiment_enabled?(EXPERIMENT_NAME)
      end
    end

    # Creates an applicator that aggregates overrides from all projects in a group.
    # Loads overrides in batches to avoid loading all project IDs and rules into memory
    # at once. Deduplicates by purl to avoid redundant override entries.
    def self.new_for_group(group)
      return NULL_APPLICATOR unless group
      return NULL_APPLICATOR unless experiment_enabled_for_group?(group)

      overrides_by_purl = {}
      limit_reached = false

      group.all_projects.each_batch(of: 500, column: :id) do |project_batch|
        rules = Security::ApprovalPolicyRule
          .license_finding_with_overrides_for_project(project_batch.select(:id))
          .order(:id) # rubocop:disable CodeReuse/ActiveRecord -- service aggregating cross-project rules

        rules.each do |rule|
          rule.license_overrides.each do |override|
            if overrides_by_purl.size >= MAX_GROUP_OVERRIDES
              limit_reached = true
              break
            end

            overrides_by_purl[override['purl']] ||= override
          end

          break if limit_reached
        end

        break if limit_reached
      end

      if limit_reached
        Gitlab::AppLogger.warn(
          message: 'LicenseOverrideApplicator: reached MAX_GROUP_OVERRIDES limit',
          group_id: group.id,
          limit: MAX_GROUP_OVERRIDES
        )
      end

      new_with_overrides(overrides_by_purl.values)
    end

    # Creates an applicator with pre-loaded overrides (skips DB query).
    # Used by new_for_group to avoid per-project DB queries.
    def self.new_with_overrides(overrides)
      new(nil, preloaded_overrides: overrides)
    end

    # @param project [Project, nil] the project to load overrides for (nil when using preloaded_overrides)
    # @param preloaded_overrides [Array<Hash>, nil] pre-loaded override hashes (skips DB query when set)
    def initialize(project, preloaded_overrides: nil)
      @project = project
      @preloaded_overrides = preloaded_overrides
    end

    # Returns true if there are any active overrides.
    def overrides?
      active_overrides.present?
    end

    # Apply overrides to an array of license hashes for a given purl.
    # Returns a new array -- does not mutate the input.
    # Handles both string-keyed hashes (from sbom_occurrences.licenses JSONB) and
    # symbol-keyed hashes (from Sbom::Component). Output format mirrors the input format.
    #
    # @param licenses [Array<Hash>, nil] license hashes
    # @param purl [String, nil] the package URL of the dependency
    # @return [Array<Hash>, nil] license hashes with overrides applied
    def apply(licenses, purl:)
      return licenses unless purl.present?

      matching_override = find_override(purl)
      return licenses unless matching_override

      mode = matching_override.fetch('mode', MODES[:patch])
      has_unknown = (licenses || []).any? { |l| unknown_license?(l) }

      return licenses unless mode == MODES[:overwrite] || has_unknown

      spdx_id, display_name, url = resolve_license_identity(matching_override['license'])
      override_license = build_override_license(spdx_id, display_name, url, licenses&.first)

      if mode == MODES[:overwrite]
        [override_license]
      else
        (licenses || []).reject { |l| unknown_license?(l) } + [override_license]
      end
    end

    private

    attr_reader :project, :preloaded_overrides

    # Returns true if ANY security orchestration policy configuration linked to
    # the project (direct or inherited from namespace) has the experiment enabled.
    def experiment_enabled_for_project?
      return false unless project

      project.all_security_orchestration_policy_configurations.any? do |config|
        config.experiment_enabled?(EXPERIMENT_NAME)
      end
    end

    def find_override(purl)
      active_overrides.find { |override| purl_matches?(purl, override['purl']) }
    end

    def active_overrides
      return preloaded_overrides if preloaded_overrides
      return [] unless experiment_enabled_for_project?

      Security::ApprovalPolicyRule
        .license_finding_with_overrides_for_project(project.id)
        .flat_map(&:license_overrides)
    end
    strong_memoize_attr :active_overrides

    def unknown_license?(license)
      # Handles both string (JSONB) and symbol hashes.
      spdx = license['spdx_identifier'] || license[:spdx_identifier]
      name = license['name'] || license[:name]
      spdx.blank? || spdx == UNKNOWN_SPDX || name == UNKNOWN_SPDX
    end

    # Builds the override license hash matching the key format of the input (string or symbol).
    def build_override_license(spdx_id, display_name, url, sample)
      if sample&.key?(:spdx_identifier)
        { spdx_identifier: spdx_id, name: display_name, url: url }
      else
        { 'spdx_identifier' => spdx_id, 'name' => display_name, 'url' => url }
      end
    end
  end
end
