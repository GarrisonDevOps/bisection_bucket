# frozen_string_literal: true

# rubocop: disable Gitlab/BoundedContexts -- this namespace is already established, embedding it deeper into another namespace would make things inconsistent.
module PackageMetadata
  module AdvisoryHelpers
    extend ActiveSupport::Concern

    def current_user_allowed?(current_user)
      return false unless current_user
      return false unless Feature.enabled?(:pm_advisory_graphql, current_user)
      return false unless ::License.feature_available?(:dependency_scanning)

      true
    end
  end
end
# rubocop: enable Gitlab/BoundedContexts
