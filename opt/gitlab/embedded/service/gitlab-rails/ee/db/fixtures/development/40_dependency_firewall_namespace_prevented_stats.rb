# frozen_string_literal: true

# Seeds the group summary table so it is populated for local development and upgrade testing.
# Fixed small counts; the real values come from the periodic refresh of the project ledger.
Gitlab::Seeder.quiet do
  model = Security::DependencyFirewallNamespacePreventedStat

  root_groups = Group.top_level.limit(5)

  root_groups.each do |group|
    model::WINDOWS.each do |window_days|
      stat = model.find_or_initialize_by(namespace_id: group.id, window_days: window_days)
      stat.update!(
        window_start: Date.current - (window_days - 1),
        vulnerabilities_prevented: 3,
        severity_critical: 1,
        severity_high: 2,
        malicious_packages_prevented: 1,
        malicious_packages_warned_only: 1,
        license_risks_prevented: 1,
        license_risks_warned_only: 2
      )
    end

    print '.'
  end
end
