# frozen_string_literal: true

# Seeds sample rows in `billable_usage_export_logs` so that the table is not empty in
# development environments. In production it is written only on offline-licensed
# instances, once per usage export an admin downloads.
Gitlab::Seeder.quiet do
  admin = Gitlab::DatabaseImporters::AdminOrganizationImporter.seeded_admin

  [
    { period_start: Date.new(2026, 8, 1), period_end: Date.new(2026, 8, 31), generated_by: admin, record_count: 62 },
    { period_start: Date.new(2026, 8, 1), period_end: Date.new(2026, 9, 30), generated_by: nil, record_count: 122 }
  ].each do |attrs|
    Utilization::BillableUsage::ExportLog.create!(
      **attrs,
      generated_at: attrs[:period_end].next_day.to_time(:utc).change(hour: 9),
      payload_checksum: SecureRandom.hex(32)
    )
  end

  print '.'
end
