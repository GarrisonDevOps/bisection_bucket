# frozen_string_literal: true

module EE
  module Gitlab
    module BackgroundMigration
      # Counts were left wrong in either direction: a deleted blocked issue lost its links through a cascading
      # foreign key, so its blockers kept counting it, and closing or reopening a blocked issue did not recount
      # its closed blockers. Recounts every issue as IssueLink.blocking_issuables_for_collection does, and 0 with
      # no link left.
      module RecountBlockingIssuesCount
        extend ActiveSupport::Concern
        extend ::Gitlab::Utils::Override

        OPENED_STATE_ID = 1
        BLOCKS_LINK_TYPE = 1

        prepended do
          operation_name :recount_blocking_issues_count
        end

        override :perform
        def perform
          each_sub_batch do |sub_batch|
            connection.execute(<<~SQL)
              WITH sub_batch AS MATERIALIZED (
                #{sub_batch.select(:id, :blocking_issues_count).limit(sub_batch_size).to_sql}
              ),
              blocking_counts AS (
                SELECT issue_links.source_id AS blocking_issue_id,
                  COUNT(CASE WHEN issues.state_id = #{OPENED_STATE_ID} THEN 1 ELSE NULL END) AS count
                FROM issue_links
                INNER JOIN issues ON issues.id = issue_links.target_id
                WHERE issue_links.link_type = #{BLOCKS_LINK_TYPE}
                  AND issue_links.source_id IN (SELECT id FROM sub_batch)
                GROUP BY issue_links.source_id
              )
              UPDATE issues
              SET blocking_issues_count = COALESCE(blocking_counts.count, 0)
              FROM sub_batch
              LEFT JOIN blocking_counts ON blocking_counts.blocking_issue_id = sub_batch.id
              WHERE issues.id = sub_batch.id
                AND sub_batch.blocking_issues_count <> COALESCE(blocking_counts.count, 0)
            SQL
          end
        end
      end
    end
  end
end
