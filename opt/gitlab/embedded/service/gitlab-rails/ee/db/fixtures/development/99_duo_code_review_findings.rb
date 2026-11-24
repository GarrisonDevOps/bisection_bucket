# frozen_string_literal: true

# Only the Duo Code Review publish step writes this table, so this fixture classifies
# merge request notes seeded earlier. The last row has no workflow or confidence.
Gitlab::Seeder.quiet do
  if Ai::DuoWorkflows::CodeReview::Finding.exists?
    print '.'
    next
  end

  merge_request = MergeRequest.joins(:notes).first
  next warn "\nSkipping duo_code_review_findings seeds: no merge request note available" unless merge_request

  notes = merge_request.notes.order(:id).limit(3).to_a
  workflow = FactoryBot.create(:duo_workflows_workflow, project: merge_request.project, user: merge_request.author)
  classifications = [
    { severity: :critical, depth: :standard, category: 'security', confidence: 9, workflow: workflow },
    { severity: :major, depth: :lite, category: 'missing-test', confidence: 6, workflow: workflow },
    { severity: :minor, depth: :standard, category: 'documentation', confidence: nil, workflow: nil }
  ]

  notes.zip(classifications).each do |note, classification|
    Ai::DuoWorkflows::CodeReview::Finding.create!(
      note: note,
      merge_request: merge_request,
      **classification
    )

    print '.'
  end
end
