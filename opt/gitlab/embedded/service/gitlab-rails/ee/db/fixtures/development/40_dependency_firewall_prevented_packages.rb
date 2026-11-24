# frozen_string_literal: true

# Seeds the prevented-packages ledger so the table is populated for local
# development and upgrade testing. Writes through bulk_upsert! because the
# buffered write path lands in a later MR of the series.
Gitlab::Seeder.quiet do
  model = Security::DependencyFirewallPreventedPackage

  packages = [
    { rule_type: 'license', identifier: 'pkg:npm/left-pad@1.3.0', severity: nil },
    { rule_type: 'malicious', identifier: 'pkg:npm/event-stream@3.3.6', severity: nil },
    { rule_type: 'risk_severity', identifier: 'pkg:npm/minimist@0.0.8', severity: 'critical' }
  ]

  Project.limit(5).each do |project|
    rows = packages.map do |package|
      blocked_at = rand(1..72).hours.ago

      {
        project_id: project.id,
        rule_type: model.rule_types[package[:rule_type]],
        identifier: package[:identifier],
        first_seen_at: blocked_at,
        last_blocked_at: blocked_at,
        # Anchored to blocked_at so a warn never predates the package being first seen.
        last_warned_at: rand < 0.5 ? blocked_at + rand(1..12).hours : nil,
        severity: model.severities[package[:severity]]
      }
    end

    model.bulk_upsert!(rows)
    print '.'
  end
end
