# frozen_string_literal: true

class OrganizationPushRuleFinder
  def initialize(container)
    @container = container
  end

  def execute
    global_rule
  end

  private

  attr_reader :container

  def global_rule
    return unless container

    OrganizationPushRule.find_by(organization: container) # rubocop: disable CodeReuse/ActiveRecord -- extracted for finder use
  end
end
