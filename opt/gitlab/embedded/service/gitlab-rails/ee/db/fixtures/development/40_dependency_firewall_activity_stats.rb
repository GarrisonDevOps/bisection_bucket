# frozen_string_literal: true

# Seeds the dependency firewall activity dashboard with hourly enforcement
# counts so the table is populated for local development and upgrade testing.
Gitlab::Seeder.quiet do
  rule = Security::DependencyFirewallPolicyRule.first

  Project.limit(5).each do |project|
    6.times do |hour|
      time = hour.hours.ago

      # `allowed` is the high-volume outcome (one per successful download) and
      # carries no rule, so it coalesces into a single bucket per hour.
      rand(1..20).times do
        Security::DependencyFirewallActivityStat.increment!(
          project_id: project.id, outcome: :allowed, time: time
        )
      end

      next unless rule

      rand(0..3).times do
        Security::DependencyFirewallActivityStat.increment!(
          project_id: project.id, rule_id: rule.id, outcome: :blocked, time: time
        )
      end

      rand(0..2).times do
        Security::DependencyFirewallActivityStat.increment!(
          project_id: project.id, rule_id: rule.id, outcome: :warned, time: time
        )
      end
    end

    print '.'
  end

  # Sanctioned fixture use; see doc/development/performance.md.
  Gitlab::ExclusiveLease.skipping_transaction_check do
    Security::DependencyFirewall::FlushActivityStatsWriteBufferCronWorker.new.perform
  end

  if Security::DependencyFirewallActivityStat.none?
    puts "\ndependency firewall activity stats: flush deferred (another flush holds the lease); " \
      "counts appear when the cron next runs"
  end
end
