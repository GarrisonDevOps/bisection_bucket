# frozen_string_literal: true

# This worker synchronizes security finding enrichments when CVE metadata is updated.
# It queries recently updated CVE enrichments, updates corresponding finding enrichments,
# and triggers MR approval updates for policies with enrichment filters.
#
# Performance note: pm_cve_enrichment (gitlab_pm schema) and security_finding_enrichments
# (gitlab_sec schema) live on different logical schemas and cannot be joined in SQL.
# We fetch updated CVE data from gitlab_pm, then issue a bulk update on gitlab_sec

module Security
  class SyncFindingEnrichmentWorker # rubocop:disable Scalability/IdempotentWorker -- Not guaranteed to be idempotent
    include ApplicationWorker

    data_consistency :sticky
    feature_category :security_policy_management
    urgency :low

    defer_on_database_health_signal :gitlab_sec, [:security_finding_enrichments], 1.minute

    BATCH_SIZE = 100
    RECENTLY_UPDATED_PERIOD = 1.hour

    def perform
      return unless should_run?

      affected_project_ids = Set.new

      scope = PackageMetadata::CveEnrichment.updated_after(RECENTLY_UPDATED_PERIOD.ago)
      iterator = Gitlab::Pagination::Keyset::Iterator.new(scope: scope)

      iterator.each_batch(of: BATCH_SIZE) do |cve_batch|
        enrichment_attributes = cve_batch.pluck(:id, :epss_score, :is_known_exploit) # rubocop:disable CodeReuse/ActiveRecord -- specific to this worker
        project_ids = bulk_update_finding_enrichments(enrichment_attributes)
        affected_project_ids.merge(project_ids)
      end

      enqueue_mr_approval_updates(affected_project_ids)
    end

    private

    def should_run?
      return false unless ::License.feature_available?(:security_orchestration_policies)
      return false if Rails.env.development? && ENV.fetch('PM_SYNC_IN_DEV', 'false') != 'true'

      true
    end

    def bulk_update_finding_enrichments(enrichment_attributes)
      connection = SecApplicationRecord.connection
      enrichment_values = build_enrichment_values(enrichment_attributes, connection)
      update_sql = build_update_finding_enrichments_sql(enrichment_values)

      result = connection.exec_query(update_sql)
      result.rows.map(&:first).uniq
    end

    def build_update_finding_enrichments_sql(enrichment_values)
      <<~SQL
        UPDATE security_finding_enrichments sfe
        SET
          epss_score       = cve_enrichment.epss_score,
          is_known_exploit = cve_enrichment.is_known_exploit,
          updated_at       = NOW()
        FROM (VALUES #{enrichment_values}) AS cve_enrichment(id, epss_score, is_known_exploit)
        WHERE sfe.cve_enrichment_id = cve_enrichment.id
        RETURNING sfe.project_id
      SQL
    end

    def build_enrichment_values(enrichment_attributes, connection)
      enrichment_attributes.map do |id, epss_score, is_known_exploit|
        "(#{connection.quote(id)}::bigint, " \
          "#{connection.quote(epss_score)}::double precision, " \
          "#{connection.quote(is_known_exploit)}::boolean)"
      end.join(', ')
    end

    def enqueue_mr_approval_updates(project_ids)
      return if project_ids.empty?

      project_ids.each_slice(BATCH_SIZE) do |project_ids_chunk|
        Security::Policy
          .for_projects(project_ids_chunk)
          .type_approval_policy
          .with_enrichment_filters
          .enabled
          .pluck(:id, 'security_policy_project_links.project_id') # rubocop:disable CodeReuse/ActiveRecord -- pluck of joined column specific to this worker
          .each do |policy_id, project_id|
            Security::SyncMergeRequestsWorker.perform_async(project_id, policy_id)
          end
      end
    end
  end
end
