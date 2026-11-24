# frozen_string_literal: true

class CiMinutesUsageMailerPreview < ActionMailer::Preview
  def out_of_minutes
    ::CiMinutesUsageMailer.notify(Group.last.root_ancestor, %w[bob@example.com])
  end

  def limit_warning
    ::CiMinutesUsageMailer.notify_limit(Group.last.root_ancestor, %w[bob@example.com], 2025, 10000, 20.25, 25)
  end
end
