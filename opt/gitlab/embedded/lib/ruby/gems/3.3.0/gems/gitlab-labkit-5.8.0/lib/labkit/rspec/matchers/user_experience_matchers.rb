# frozen_string_literal: true

# RSpec matchers for testing Labkit UserExperience functionality
#
# This file must be explicitly required in your test setup:
#   require 'labkit/rspec/matchers'

raise LoadError, "RSpec is not loaded. Please require 'rspec' before requiring 'labkit/rspec/matchers'" unless defined?(RSpec)

module Labkit
  module RSpec
    module Matchers
      # Helper module for UserExperience functionality
      module UserExperience
        def attributes(user_experience_id)
          raise ArgumentError, "user_experience_id is required" if user_experience_id.nil?

          definition = Labkit::UserExperienceSli::Registry.new[user_experience_id]
          definition.to_h.slice(:user_experience_id, :feature_category, :urgency)
        end

        def checkpoint_counter
          Labkit::Metrics::Client.get(:gitlab_user_experience_checkpoint_total)
        end

        def total_counter
          Labkit::Metrics::Client.get(:gitlab_user_experience_total)
        end

        def apdex_counter
          Labkit::Metrics::Client.get(:gitlab_user_experience_apdex_total)
        end
      end
    end
  end
end

# Matcher for verifying UserExperience start metrics instrumentation.
#
# Usage:
#   expect { subject }.to start_user_experience('rails_request')
#
# This matcher verifies that the following metric is incremented:
# - gitlab_user_experience_checkpoint_total (with checkpoint=start)
#
# Parameters:
# - user_experience_id: Required. The ID of the user experience (e.g., 'rails_request')
RSpec::Matchers.define :start_user_experience do |user_experience_id|
  include Labkit::RSpec::Matchers::UserExperience

  description { "start user experience '#{user_experience_id}'" }
  supports_block_expectations

  match do |actual|
    labels = attributes(user_experience_id)

    checkpoint_before = checkpoint_counter&.get(labels.merge(checkpoint: "start")).to_i

    actual.call

    checkpoint_after = checkpoint_counter&.get(labels.merge(checkpoint: "start")).to_i

    @checkpoint_change = checkpoint_after - checkpoint_before

    @checkpoint_change == 1
  end

  failure_message do
    "Failed to checkpoint user experience '#{user_experience_id}':\n" \
      "expected checkpoint='start' counter to increase by 1, but increased by #{@checkpoint_change}"
  end
end

# Matcher for verifying UserExperience checkpoint metrics instrumentation.
#
# Usage:
#   expect { subject }.to checkpoint_user_experience('rails_request')
#
# This matcher verifies that the following metric is incremented:
# - gitlab_user_experience_checkpoint_total (with checkpoint=intermediate)
#
# Parameters:
# - user_experience_id: Required. The ID of the user experience (e.g., 'rails_request')
RSpec::Matchers.define :checkpoint_user_experience do |user_experience_id, by: 1|
  include Labkit::RSpec::Matchers::UserExperience

  description { "checkpoint user experience '#{user_experience_id}'" }
  supports_block_expectations

  match do |actual|
    labels = attributes(user_experience_id)

    checkpoint_before = checkpoint_counter&.get(labels.merge(checkpoint: "intermediate")).to_i

    actual.call

    checkpoint_after = checkpoint_counter&.get(labels.merge(checkpoint: "intermediate")).to_i
    @checkpoint_change = checkpoint_after - checkpoint_before

    # Automatic checkpoints can be created in-between depending on the context,
    # such as pushing experiences to background jobs. For this reason, we check
    # that the value increases by at least "by".
    @checkpoint_change >= by
  end

  failure_message do
    "Failed to checkpoint user experience '#{user_experience_id}':\n" \
      "expected checkpoint='intermediate' counter to increase by at least #{by}, but increased by #{@checkpoint_change}"
  end

  match_when_negated do |actual|
    labels = attributes(user_experience_id)

    checkpoint_before = checkpoint_counter&.get(labels.merge(checkpoint: "intermediate")).to_i

    actual.call

    checkpoint_after = checkpoint_counter&.get(labels.merge(checkpoint: "intermediate")).to_i
    @checkpoint_change = checkpoint_after - checkpoint_before

    @checkpoint_change.zero?
  end

  failure_message_when_negated do
    "Expected user experience '#{user_experience_id}' NOT to checkpoint:\n" \
      "expected checkpoint='intermediate' counter not to increase, but increased by #{@checkpoint_change}"
  end
end

# Alias for checkpoint_user_experience matcher
RSpec::Matchers.alias_matcher :resume_user_experience, :checkpoint_user_experience

# Matcher for verifying UserExperience completion metrics instrumentation.
#
# Usage:
#   expect { subject }.to complete_user_experience('rails_request')
#
# This matcher verifies that the following metrics are incremented with specific labels:
# - gitlab_user_experience_checkpoint_total (with checkpoint=end)
# - gitlab_user_experience_total (with error=false)
# - gitlab_user_experience_apdex_total (with success=true)
#
# Parameters:
# - user_experience_id: Required. The ID of the user experience (e.g., 'rails_request')
# - error: Optional. The expected error flag for gitlab_user_experience_total (false by default)
# - success: Optional. The expected success flag for gitlab_user_experience_apdex_total (true by default)
RSpec::Matchers.define :complete_user_experience do |user_experience_id, error: false, success: true|
  include Labkit::RSpec::Matchers::UserExperience

  description { "complete user experience '#{user_experience_id}'" }
  supports_block_expectations

  match do |actual|
    labels = attributes(user_experience_id)

    checkpoint_before = checkpoint_counter&.get(labels.merge(checkpoint: "end")).to_i
    total_before = total_counter&.get(labels.merge(error: error)).to_i
    apdex_before = apdex_counter&.get(labels.merge(success: success)).to_i

    actual.call

    checkpoint_after = checkpoint_counter&.get(labels.merge(checkpoint: "end")).to_i
    total_after = total_counter&.get(labels.merge(error: error)).to_i
    apdex_after = apdex_counter&.get(labels.merge(success: success)).to_i
    @checkpoint_change = checkpoint_after - checkpoint_before
    @total_change = total_after - total_before
    @apdex_change = apdex_after - apdex_before

    @checkpoint_change == 1 && @total_change == 1 && @apdex_change == (error ? 0 : 1)
  end

  failure_message do
    "Failed to complete user experience '#{user_experience_id}':\n" \
      "expected checkpoint='end' counter to increase by 1, but increased by #{@checkpoint_change}\n" \
      "expected total='error: #{error}' counter to increase by 1, but increased by #{@total_change}\n" \
      "expected apdex='success: #{success}' counter to increase by #{error ? 0 : 1}, but increased by #{@apdex_change}"
  end

  match_when_negated do |actual|
    labels = attributes(user_experience_id)

    checkpoint_before = checkpoint_counter&.get(labels.merge(checkpoint: "end")).to_i
    total_before = total_counter&.get(labels.merge(error: error)).to_i
    apdex_before = apdex_counter&.get(labels.merge(success: success)).to_i

    actual.call

    checkpoint_after = checkpoint_counter&.get(labels.merge(checkpoint: "end")).to_i
    total_after = total_counter&.get(labels.merge(error: error)).to_i
    apdex_after = apdex_counter&.get(labels.merge(success: success)).to_i
    @checkpoint_change = checkpoint_after - checkpoint_before
    @total_change = total_after - total_before
    @apdex_change = apdex_after - apdex_before

    @checkpoint_change.zero? && @total_change.zero? && @apdex_change.zero?
  end

  failure_message_when_negated do
    "Failed user experience '#{user_experience_id}' NOT to complete:\n" \
      "expected checkpoint='end' counter to increase by 0, but increased by #{@checkpoint_change}\n" \
      "expected total='error: #{error}' counter to increase by 0, but increased by #{@total_change}\n" \
      "expected apdex='success: #{success}' counter to increase by 0, but increased by #{@apdex_change}"
  end
end

# Matcher for verifying UserExperience observed metrics instrumentation.
#
# Usage:
#   expect { subject }.to observed_user_experience('rails_request')
#
# This matcher verifies that the following metrics are incremented with specific labels:
# - gitlab_user_experience_checkpoint_total (with checkpoint=start)
# - gitlab_user_experience_checkpoint_total (with checkpoint=end)
# - gitlab_user_experience_total (with error=false)
# - gitlab_user_experience_apdex_total (with success=true)
#
# Parameters:
# - user_experience_id: Required. The ID of the user experience (e.g., 'rails_request')
# - error: Optional. The expected error flag for gitlab_user_experience_total (false by default)
# - success: Optional. The expected success flag for gitlab_user_experience_apdex_total (true by default)
RSpec::Matchers.define :observed_user_experience do |user_experience_id, error: false, success: true|
  include Labkit::RSpec::Matchers::UserExperience

  description { "observe user experience '#{user_experience_id}'" }
  supports_block_expectations

  match do |actual|
    labels = attributes(user_experience_id)

    start_before = checkpoint_counter&.get(labels.merge(checkpoint: "start")).to_i
    end_before = checkpoint_counter&.get(labels.merge(checkpoint: "end")).to_i
    total_before = total_counter&.get(labels.merge(error: error)).to_i
    apdex_before = apdex_counter&.get(labels.merge(success: success)).to_i

    actual.call

    start_after = checkpoint_counter&.get(labels.merge(checkpoint: "start")).to_i
    end_after = checkpoint_counter&.get(labels.merge(checkpoint: "end")).to_i
    total_after = total_counter&.get(labels.merge(error: error)).to_i
    apdex_after = apdex_counter&.get(labels.merge(success: success)).to_i

    @start_change = start_after - start_before
    @end_change = end_after - end_before
    @total_change = total_after - total_before
    @apdex_change = apdex_after - apdex_before

    @start_change == 1 && @end_change == 1 && @total_change == 1 && @apdex_change == (error ? 0 : 1)
  end

  failure_message do
    "Failed to observe user experience '#{user_experience_id}':\n" \
      "expected checkpoint='start' counter to increase by 1, but increased by #{@start_change}\n" \
      "expected checkpoint='end' counter to increase by 1, but increased by #{@end_change}\n" \
      "expected total='error: #{error}' counter to increase by 1, but increased by #{@total_change}\n" \
      "expected apdex='success: #{success}' counter to increase by #{error ? 0 : 1}, but increased by #{@apdex_change}"
  end
end

# Backward compatibility matchers for CoveredExperience
RSpec::Matchers.alias_matcher :start_covered_experience, :start_user_experience
RSpec::Matchers.alias_matcher :checkpoint_covered_experience, :checkpoint_user_experience
RSpec::Matchers.alias_matcher :resume_covered_experience, :checkpoint_user_experience
RSpec::Matchers.alias_matcher :complete_covered_experience, :complete_user_experience
