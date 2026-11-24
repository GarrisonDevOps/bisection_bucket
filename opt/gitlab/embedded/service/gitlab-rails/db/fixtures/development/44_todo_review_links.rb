# frozen_string_literal: true

# Seeds review_submitted to-do items linked to the review that raised them, so
# migrations touching todo_review_links are exercised by db:migrate:multi-version-upgrade.
class Gitlab::Seeder::TodoReviewLinks
  REVIEW_COUNT = 2

  attr_reader :merge_request, :reviewer

  def initialize
    @merge_request = MergeRequest.first
    @reviewer = User.where.not(id: merge_request&.author_id).first
  end

  def seed!
    return warn_missing_dependencies unless merge_request && reviewer

    (REVIEW_COUNT - seeded_count).clamp(0, REVIEW_COUNT).times do
      seed_link
      print '.'
    end
  end

  private

  def warn_missing_dependencies
    warn "\nSkipping to-do review link seeds: no merge request or second user available"
  end

  # Re-runs reuse the rows already seeded for this reviewer and merge request.
  def seeded_count
    Todos::ReviewLink.joins(:todo)
      .where(todos: { author_id: reviewer.id, target_id: merge_request.id, target_type: 'MergeRequest' })
      .count
  end

  def seed_link
    review = Review.create!(author: reviewer, merge_request: merge_request, project: merge_request.target_project)

    todo = Todo.create!(
      user: merge_request.author,
      author: reviewer,
      project: merge_request.target_project,
      target: merge_request,
      action: Todo::REVIEW_SUBMITTED,
      state: 'done'
    )

    Todos::ReviewLink.create!(todo: todo, project_id: todo.project_id, review: review)
  end
end

Gitlab::Seeder.quiet do
  puts "\nGenerating to-do review links"

  Gitlab::Seeder::TodoReviewLinks.new.seed!
rescue StandardError => e
  warn "\nError seeding to-do review links: #{e}"
end
