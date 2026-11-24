# frozen_string_literal: true

module Types
  module Security
    module ScanProfiles
      class ConfigurationType < BaseUnion
        graphql_name 'ScanProfileConfiguration'
        description 'Effective configuration for a scan profile trigger, resolved by scan type, ' \
          'and by trigger type for triage and remediation profiles.'

        # A triage and remediation profile has one configuration schema per trigger type, so unlike the
        # other scan types its concrete type is selected by the trigger rather than the scan type.
        TRIAGE_AND_REMEDIATION_TYPES = {
          sast_false_positive: ::Types::Security::ScanProfiles::SastFalsePositiveConfigurationType,
          sast_vulnerability_resolution: ::Types::Security::ScanProfiles::SastVulnerabilityResolutionConfigurationType,
          secret_detection_false_positive:
            ::Types::Security::ScanProfiles::SecretDetectionFalsePositiveConfigurationType,
          vulnerability_enrichment: ::Types::Security::ScanProfiles::VulnerabilityEnrichmentConfigurationType
        }.freeze

        possible_types ::Types::Security::ScanProfiles::AutoRemediationConfigurationType,
          ::Types::Security::ScanProfiles::BusinessLogicConfigurationType,
          ::Types::Security::ScanProfiles::DependencyScanningConfigurationType,
          ::Types::Security::ScanProfiles::SastConfigurationType,
          ::Types::Security::ScanProfiles::SecretDetectionConfigurationType,
          *TRIAGE_AND_REMEDIATION_TYPES.values

        # Authorization happens at the parent level (ScanProfileType); each possible type skips
        # granular-token auth for the same reason, so the union authorizes unconditionally.
        # This override is also required because GitLab's BaseUnion.authorized? delegates to
        # `resolve_type(...).authorized?`, which would break on the `[type, value]` tuple below.
        def self.authorized?(_object, _context)
          true
        end

        # `object` is a Security::ScanProfileTrigger. The effective configuration is the scan-type
        # defaults deep-merged with the trigger's stored overrides. Both the concrete type and the
        # value it reads from are selected by the profile's scan type; scan types without a typed
        # configuration resolve to `nil`, so the field is `null`.
        #
        # When the query is scoped to a project (see ProjectType#security_scan_profiles), the project
        # is threaded through so project-specific overrides (e.g. the Duo dependency-bump upgrade
        # policy) are reflected; at group level no single project applies, so it is nil.
        def self.resolve_type(object, context)
          effective = ::Security::ScanProfiles::Configuration.effective_for(
            object.scan_profile, object, project: context[:scan_profile_project]
          )

          case object.scan_profile.scan_type&.to_sym
          when :business_logic
            [BusinessLogicConfigurationType, effective]
          when :dependency_scanning
            [DependencyScanningConfigurationType, effective]
          when :dependency_scanning_post_processing
            [AutoRemediationConfigurationType, effective[:auto_remediation]]
          when :sast
            [SastConfigurationType, effective]
          when :secret_detection
            [SecretDetectionConfigurationType, effective]
          when :triage_and_remediation
            resolve_triage_and_remediation_type(object, effective)
          end
        end

        private_class_method def self.resolve_triage_and_remediation_type(trigger, effective)
          return [AutoRemediationConfigurationType, effective[:auto_remediation]] if trigger.sbom_ingested?

          type = TRIAGE_AND_REMEDIATION_TYPES[trigger.trigger_type&.to_sym]

          [type, effective] if type
        end
      end
    end
  end
end
