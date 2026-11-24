# frozen_string_literal: true

# Sorts after 99_billable_usage_daily_namespace_aggregates.rb, whose rows it totals.
Gitlab::Seeder.quiet do
  Utilization::BillableUsage::RefreshDailyTotalsService.new.execute

  print '.' * Utilization::BillableUsage::DailyTotal.count
end
