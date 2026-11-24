# frozen_string_literal: true

module ArtifactRegistry
  # An organization's top-level groups, capped at two: enough to tell
  # none, exactly one and several apart. At GA a GitLab.com organization has
  # exactly one, which bills for Artifact Registry and scopes its audit events.
  module TopLevelGroups
    def self.first_two(organization)
      organization.groups.top_level.limit(2).to_a
    end
  end
end
