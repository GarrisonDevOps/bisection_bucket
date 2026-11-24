# frozen_string_literal: true

module Security
  module DefaultScanProfilesHelper
    SECURITY_REVIEW_PRESET_KEY = 'business_logic_security_review'

    TRIAGE_AND_REMEDIATION_PRESET_DETAILS = {
      conservative: {
        name: 'Triage and Remediation (Conservative)',
        description: "Start with the safest level of automated triage and remediation for your project. " \
          "This profile covers critical and high severity findings only, and vulnerability fixes and false " \
          "positive detection run only when you trigger them. Dependency upgrades stay within patch and minor " \
          "versions, capped at 5 open merge requests at a time."
      },
      standard: {
        name: 'Triage and Remediation (Standard)',
        description: "Apply GitLab's recommended triage and remediation settings to your security findings. " \
          "This profile covers medium severity and above, running detection, enrichment, vulnerability fixes, " \
          "and dependency upgrades automatically as new findings appear. Dependency upgrades stay within minor " \
          "versions and are capped at 30 open merge requests at a time."
      },
      proactive: {
        name: 'Triage and Remediation (Proactive)',
        description: "Extend triage and remediation to the widest range of findings in your project. " \
          "This profile covers every severity level, including informational findings, and runs every " \
          "capability automatically as issues are detected. Dependency upgrades can move all the way to the " \
          "latest version, including major version bumps."
      }
    }.freeze

    def self.default_scan_profiles
      [
        build_secret_detection_scan_profile,
        build_sast_scan_profile,
        build_dependency_scanning_scan_profile,
        build_dependency_scanning_post_processing_profile,
        build_business_logic_scan_profile,
        build_business_logic_security_review_scan_profile,
        build_skillguard_scan_profile,
        *build_triage_and_remediation_profiles
      ]
    end

    def self.build_secret_detection_scan_profile
      Security::ScanProfile.new(
        scan_type: :secret_detection,
        name: 'Secret Detection (default)',
        description: "Protect your repository from leaked secrets like API keys, tokens, and passwords. " \
          "This profile uses industry-standard rules optimized to minimize false positives. " \
          "When enabled, secrets are detected in real time during git push events and blocked " \
          "before they're committed.",
        gitlab_recommended: true,
        scan_profile_triggers_attributes: [
          { trigger_type: :git_push_event },
          { trigger_type: :default_branch_pipeline },
          { trigger_type: :merge_request_pipeline }
        ]
      )
    end

    def self.build_sast_scan_profile
      Security::ScanProfile.new(
        scan_type: :sast,
        name: 'SAST (default)',
        description: "Identify security vulnerabilities in your source code before they reach production. " \
          "This profile scans for issues like SQL injection, cross-site scripting, hardcoded credentials, and " \
          "insecure data handling. It uses GitLab's curated ruleset, continuously updated to detect real issues " \
          "while minimizing false positives.",
        gitlab_recommended: true,
        scan_profile_triggers_attributes: [
          { trigger_type: :default_branch_pipeline },
          { trigger_type: :merge_request_pipeline }
        ]
      )
    end

    def self.build_dependency_scanning_scan_profile
      Security::ScanProfile.new(
        scan_type: :dependency_scanning,
        name: 'Dependency Scanning (default)',
        description: "Identify known vulnerabilities in your project's open source dependencies before they reach " \
          "production. This profile scans all dependencies — including transitive ones — across merge request and " \
          "branch pipelines, so security issues are caught early and compared against your default branch.",
        gitlab_recommended: true,
        scan_profile_triggers_attributes: [
          { trigger_type: :default_branch_pipeline },
          { trigger_type: :merge_request_pipeline }
        ]
      )
    end

    def self.build_dependency_scanning_post_processing_profile
      Security::ScanProfile.new(
        scan_type: :dependency_scanning_post_processing,
        name: 'Dependency Scanning Auto-Remediation (default)',
        description: "Automatically resolve known vulnerabilities in your project's open source dependencies. " \
          "This profile opens merge requests that upgrade affected dependencies to secure versions whenever new " \
          "vulnerabilities are detected, so fixes are proposed for you without manual triage.",
        gitlab_recommended: true,
        scan_profile_triggers_attributes: [
          { trigger_type: :sbom_ingested }
        ]
      )
    end

    def self.build_triage_and_remediation_profiles
      presets = Security::ScanProfiles::Configuration::Defaults::TriageAndRemediation::PRESETS

      presets.map do |preset, trigger_configurations|
        build_triage_and_remediation_profile(preset, trigger_configurations)
      end
    end

    def self.build_triage_and_remediation_profile(preset, trigger_configurations)
      details = TRIAGE_AND_REMEDIATION_PRESET_DETAILS.fetch(preset)

      profile = Security::ScanProfile.new(
        scan_type: :triage_and_remediation,
        name: details[:name],
        description: details[:description],
        gitlab_recommended: true
      )
      profile.preset_key = "triage_and_remediation_#{preset}"

      trigger_configurations.each do |trigger_type, configuration|
        build_triage_and_remediation_trigger(profile, trigger_type, configuration)
      end

      profile
    end

    def self.build_triage_and_remediation_trigger(profile, trigger_type, configuration)
      trigger = profile.scan_profile_triggers.build(trigger_type: trigger_type)

      overrides = Security::ScanProfiles::Configuration.strip_defaults(
        configuration,
        Security::ScanProfiles::Configuration.defaults_for(:triage_and_remediation, trigger_type)
      )
      return if overrides.blank?

      trigger.configuration = Security::ScanProfiles::Configuration.new(
        scan_profile: profile, configuration: overrides, trigger_type: trigger_type
      )
    end

    def self.build_business_logic_scan_profile
      Security::ScanProfile.new(
        scan_type: :business_logic,
        name: 'Business Logic (default)',
        description: "Use an AI agent to find business logic vulnerabilities in your source code, like missing " \
          "authorization, broken object-level access, and mass assignment. This profile scans the files a " \
          "merge request changes, after the merge request's head pipeline succeeds. If the project has no " \
          "CI/CD pipelines, no merge request scans run.",
        gitlab_recommended: true,
        scan_profile_triggers_attributes: [{ trigger_type: :merge_request_pipeline }]
      )
    end

    def self.build_business_logic_security_review_scan_profile
      profile = Security::ScanProfile.new(
        scan_type: :business_logic,
        name: 'Security Review',
        description: "Use an AI agent to review merge requests for security vulnerabilities, including business " \
          "logic flaws. A review runs when a merge request is created or marked as ready, as the merge " \
          "request author. Findings are posted only as review threads on the merge request. They are not " \
          "added to the Vulnerability Report or the merge request security widget.",
        gitlab_recommended: true
      )
      profile.preset_key = SECURITY_REVIEW_PRESET_KEY

      trigger = profile.scan_profile_triggers.build(trigger_type: :merge_request_pipeline)
      trigger.configuration = Security::ScanProfiles::Configuration.new(
        scan_profile: profile, configuration: { post_review_threads: true }, trigger_type: :merge_request_pipeline
      )

      profile
    end

    def self.build_skillguard_scan_profile
      Security::ScanProfile.new(
        scan_type: :skillguard,
        name: 'SkillGuard (default)',
        description: "Use an AI scanner to find security risks in the AI agent skill files in your repository, " \
          "such as prompt injection, credential exfiltration, and unsafe command execution.",
        gitlab_recommended: true,
        scan_profile_triggers_attributes: [{ trigger_type: :default_branch_pipeline }]
      )
    end
  end
end
