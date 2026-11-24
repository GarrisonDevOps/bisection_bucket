# frozen_string_literal: true

module ProjectSecurityScannersInformation
  include ::Gitlab::Utils::StrongMemoize
  include ::Security::LatestPipelineInformation

  def available_scanners
    scanners = all_security_scanners
    scanners -= [:business_logic] unless business_logic_enabled?
    scanners.filter_map { |scanner| scanner.upcase.to_s if feature_available?(scanner) }
  end

  def enabled_scanners
    all_security_scanners.filter_map { |scanner| scanner.upcase.to_s if scanner_enabled?(scanner) }
  end

  def scanners_run_in_last_pipeline
    reports = latest_builds_reports(only_successful_builds: true)
    return [] if reports.empty?

    all_security_scanners.filter_map { |scanner| scanner.upcase.to_s if reports.include?(scanner) }
  end

  private

  def all_security_scanners
    scanners = ::Enums::Security.analyzer_types.keys
    scanners -= [:business_logic] unless business_logic_enabled?
    scanners -= [:skillguard] unless ::Feature.enabled?(:skillguard_analyzer, root_ancestor)
    scanners
  end

  def business_logic_enabled?
    ::Ai::Catalog::FoundationalFlow::BlSecurity::Definition.scan_profiles_enabled_for?(root_ancestor)
  end
end
