# frozen_string_literal: true

Gitlab::Seeder.quiet do
  work_items = WorkItem.where.not(author_id: nil).take(3)

  if work_items.empty?
    puts "\nSkipping work item decision seeds (no work items with an author found)"
    next
  end

  work_items.each do |work_item|
    next if work_item.decisions.exists?

    pending = WorkItems::Decision.create!(
      work_item: work_item,
      author: work_item.author,
      title: 'Which storage backend should we use?',
      description: 'Open question seeded for the decision log.'
    )
    pending.options.create!(content: 'Use PostgreSQL', recommended: true)
    pending.options.create!(content: 'Use Redis')

    resolved = WorkItems::Decision.create!(
      work_item: work_item,
      author: work_item.author,
      title: 'Should the rollout be gated behind a feature flag?',
      resolved_at: Time.current,
      resolved_by: work_item.author,
      resolution_rationale: 'Safer rollout; the flag can be removed later.'
    )
    resolved.options.create!(content: 'Yes, use a feature flag', selected: true)
    resolved.options.create!(content: 'Ship unflagged')

    print '.'
  end
end
