# frozen_string_literal: true

# Each Sentry field call with distinct arguments is its own reactive cache entry and refresh job,
# so aliasing a field fans out. The count is per operation; multiplexed operations count separately
# and the per-user entry cap (error_tracking_sentry_cache_entries_per_user) remains the backstop.
module SentryFieldCallLimit # rubocop:disable Gitlab/BoundedContexts -- resolver concern, like the others in this directory
  extend ActiveSupport::Concern

  ENABLED = ->(object) do
    project = object.respond_to?(:gitlab_project) ? object.gitlab_project : object

    Feature.enabled?(:error_tracking_graphql_field_call_limit, project)
  end

  # Field descriptions must name the flag and the behaviour while it is off, per the GraphQL styleguide.
  def self.description(limit)
    count = limit == 1 ? 'once' : "#{limit} times"

    'When the `error_tracking_graphql_field_call_limit` feature flag is enabled for the project, ' \
      "this field can only be resolved #{count} per operation."
  end

  class_methods do
    def limit_sentry_field_calls(limit)
      extension(::Gitlab::Graphql::Limit::FieldCallCount, limit: limit, enabled: ENABLED)
    end
  end
end
