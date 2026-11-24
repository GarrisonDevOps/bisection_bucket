# frozen_string_literal: true

# Nothing writes to this table until GitLab Duo Chat records token usage, so this
# fixture gives db:migrate:multi-version-upgrade a row to exercise.
Gitlab::Seeder.quiet do
  group = Group.top_level.first
  user = User.first
  next warn "\nSkipping ai_token_daily_usages seeds: no top-level group or user available" unless group && user

  Ai::TokenDailyUsage.find_or_create_by!(
    usage_date: Time.current.utc.to_date,
    organization_id: group.organization_id,
    traversal_ids: group.traversal_ids,
    user_id: user.id,
    feature: :chat,
    model: 'claude-sonnet-4-6'
  ) do |usage|
    usage.input_tokens = 1_200
    usage.output_tokens = 300
    usage.events_count = 2
  end

  print '.'
end
