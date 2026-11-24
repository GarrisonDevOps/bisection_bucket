# frozen_string_literal: true

module EE
  module Snippet
    extend ActiveSupport::Concern
    extend ::Gitlab::Utils::Override

    prepended do
      include Elastic::SnippetsSearch
      include UsageStatistics

      scope :preload_for_indexing, -> { preload(:author, project: :project_feature) }
      scope :by_repository_storage, ->(storage) do
        joins(snippet_repository: :shard).where(shards: { name: storage })
      end

      scope :with_ip_restrictions, -> do
        only_project_snippets.joins(project: { group: :ip_restrictions })
      end

      scope :allowed_for_ip, ->(current_ip) do
        out_of_ip_range = <<-SQL.squish
          NOT EXISTS (
            SELECT 1
            FROM ip_restrictions
            WHERE group_id = namespaces.id
            AND inet(?) <<= range::inet
          )
        SQL

        restricted_group_snippets = with_ip_restrictions.where(out_of_ip_range, current_ip)
        where.not(id: restricted_group_snippets.select(:id))
      end
    end

    override :repository_size_checker
    def repository_size_checker
      strong_memoize(:repository_size_checker) do
        ::Gitlab::RepositorySizeChecker.new(
          current_size_proc: -> { repository.size.megabytes },
          limit: ::Gitlab::CurrentSettings.snippet_size_limit,
          namespace: project&.namespace
        )
      end
    end
  end
end
