# ee/app/services/vulnerabilities/reads/upsert_service.rb
# frozen_string_literal: true

module Vulnerabilities
  module Reads
    # This class will update vulnerability reads for a set of corresponding vulnerability records
    # according to the passed attributes set.
    #
    # It can operate in two modes:
    # 1. Vulnerability-based (legacy): Pass vulnerabilities and it derives findings from them
    # 2. Finding-based (ref-aware): Pass findings directly to ensure context-specific
    #    interactions are propagated only to the correctly contexted vulnerability_read
    #
    # If any of the passed vulnerabilities does not have a corresponding read, it will ensure it
    # exists in the created state.
    #
    # If no attributes are passed, it will only ensure that the vulnerabilities have corresponding
    # vulnerability reads created.

    class UpsertService
      include BaseServiceUtility

      BATCH_SIZE = 1000

      # The DB trigger sets these from the link tables without touching the vulnerability row,
      # so nothing else reindexes the vulnerability in Elasticsearch.
      TRIGGER_MAINTAINED_LINK_ATTRIBUTES = %i[has_issues has_merge_request].freeze

      def initialize(vulnerabilities, attributes = {}, projects: [], update_all_vulnerabilities: false, findings: [])
        @attributes = attributes
        @vulnerabilities = ensure_vulnerability_relation(vulnerabilities)
        # Project is only needed for feature flag purposes
        @projects = Array(projects)
        # temporary needed when turn_off_vulnerability_read_create_db_trigger_function is disabled
        # we still want to use the service to update fields not updated by the trigger
        @update_all_vulnerabilities = update_all_vulnerabilities
        @findings_by_vulnerability_id = build_findings_index(findings)
      end

      def execute
        return if @vulnerabilities.empty?

        # Until we globally enable the FF, we have to filter off vulns for projects where the FF is not on so
        # that we can make sure to run the service for projects where the trigger is switched off, else we'll
        # cause data inconsistencies.
        unless @update_all_vulnerabilities
          @projects, trigger_path_projects = @projects.partition do |p|
            Feature.enabled?(:turn_off_vulnerability_read_create_db_trigger_function, p)
          end

          sync_trigger_maintained_attributes_to_es(trigger_path_projects)
        end

        @vulnerabilities = @vulnerabilities.with_project(@projects)

        @vulnerabilities.each_batch(of: BATCH_SIZE) do |vulnerability_batch|
          SecApplicationRecord.feature_flagged_transaction_for(@projects) do
            vulns_missing_reads = vulnerability_batch.left_joins(:vulnerability_read)
                                                     .merge(Vulnerabilities::Read.by_vulnerabilities(nil))
                                                     .pluck_primary_key
            new_read_vulnerability_ids = create_missing_reads(vulns_missing_reads)

            next unless attributes.any?

            vulnerability_read_batch = scoped_vulnerability_reads(vulnerability_batch, new_read_vulnerability_ids)

            vulnerability_read_batch.update_all(attributes)

            SecApplicationRecord.current_transaction.after_commit do
              log_batch("Updated vulnerability_reads", vulnerability_read_batch)
              Vulnerabilities::BulkEsOperationService.new(vulnerability_batch).execute
            end
          end
        end

        success
      end

      private

      attr_reader :attributes, :batch_size

      # We do this to avoid nesting a subquery of the vulnerabilities in itself if passed a relation.
      def ensure_vulnerability_relation(vulnerabilities_parameter)
        if vulnerabilities_parameter.is_a?(ActiveRecord::Relation)
          vulnerabilities_parameter.dup
        else
          Vulnerability.by_ids(vulnerabilities_parameter)
        end
      end

      def build_findings_index(findings)
        Array(findings).index_by(&:vulnerability_id)
      end

      def finding_for(vulnerability)
        @findings_by_vulnerability_id[vulnerability.id] || vulnerability.finding
      end

      def sync_trigger_maintained_attributes_to_es(trigger_path_projects)
        return if trigger_path_projects.empty?
        return unless attributes.keys.map(&:to_sym).intersect?(TRIGGER_MAINTAINED_LINK_ATTRIBUTES)

        trigger_path_vulnerabilities = @vulnerabilities.with_project(trigger_path_projects)

        SecApplicationRecord.current_transaction.after_commit do
          trigger_path_vulnerabilities.each_batch(of: BATCH_SIZE) do |vulnerability_batch|
            Vulnerabilities::BulkEsOperationService.new(vulnerability_batch).execute
          end
        end
      end

      def scoped_vulnerability_reads(vulnerability_batch, exclude_vulnerability_ids)
        reads = Vulnerabilities::Read.by_vulnerabilities(vulnerability_batch)
                                     .excluding_vulnerabilities(exclude_vulnerability_ids)

        context_id = @attributes[:security_project_tracked_context_id]
        return reads unless context_id

        # Reads inserted by the legacy DB trigger have no tracked context yet, so they must be included
        # for the update to assign one.
        reads.by_tracked_context([context_id, nil])
      end

      def create_missing_reads(missing_read_vuln_ids)
        return [] if missing_read_vuln_ids.empty?

        # rubocop:disable CodeReuse/ActiveRecord -- This is a very specific set of eager and pre loads needed for
        # building a full vulnerability record in as few queries as possible, but needing to cross DB boundaries.
        missing_vulnerability_batch = Vulnerability.by_ids(missing_read_vuln_ids)
                                                   .eager_load(
                                                     :issue_links,
                                                     :merge_request_links,
                                                     findings: [
                                                       :remediations,
                                                       :scanner,
                                                       :identifiers,
                                                       { finding_identifiers: :identifier }
                                                     ]
                                                   )
                                                   .preload(
                                                     :notes,
                                                     :merge_requests,
                                                     :related_issues,
                                                     :external_issue_links,
                                                     project: [
                                                       :route,
                                                       { project_namespace: :route },
                                                       { namespace: :route }
                                                     ]
                                                   )
        # rubocop:enable CodeReuse/ActiveRecord

        batch = build_vulnerability_reads_batch(missing_vulnerability_batch)
        new_read_ids = perform_bulk_insert(batch)
        ::SecApplicationRecord.current_transaction.after_commit do
          Vulnerabilities::BulkEsOperationService.new(missing_vulnerability_batch).execute
        end
        log_batch("New vulnerability_reads created", batch)
        new_read_ids
      end

      def build_vulnerability_reads_batch(vulnerability_batch)
        vulnerability_batch.filter_map do |vulnerability|
          next unless vulnerability.present_on_default_branch?

          finding = finding_for(vulnerability)
          next unless finding

          build_vulnerability_read(vulnerability, finding)
        end
      end

      def perform_bulk_insert(vulnerability_reads_for_insert)
        # rubocop:disable Search/VulnerabilityBulkOperationElasticsearchSync -- ES sync handled by
        # the after_commit block in create_missing_reads
        ::Vulnerabilities::Read.bulk_upsert!(
          vulnerability_reads_for_insert,
          unique_by: %i[uuid],
          returns: [:vulnerability_id]
        ) do |item_attrs|
          item_attrs.delete('id') # `id` is an auto-generated sequence
        end
        # rubocop:enable Search/VulnerabilityBulkOperationElasticsearchSync
      end

      def build_vulnerability_read(vulnerability, finding)
        ::Vulnerabilities::Read.new(
          {
            vulnerability_id: vulnerability.id,
            project_id: vulnerability.project_id,
            uuid: finding.uuid,
            scanner_id: finding.scanner_id,
            severity: vulnerability.severity,
            state: vulnerability.state,
            report_type: vulnerability.report_type,
            resolved_on_default_branch: vulnerability.resolved_on_default_branch,
            # This map won't cause an N+1 thanks to the identifier eager_load earlier in the service
            identifier_names: finding.identifiers.map(&:name),
            location_image: finding.location['image'],
            has_remediations: vulnerability.has_remediations?,
            cluster_agent_id: vulnerability.location.dig('kubernetes_resource', 'agent_id'),
            traversal_ids: vulnerability.project.namespace.traversal_ids,
            archived: vulnerability.project.archived?,
            auto_resolved: vulnerability.auto_resolved?,
            security_project_tracked_context_id: finding.security_project_tracked_context_id,
            # Derived defaults; a value passed by the caller in @attributes takes precedence.
            has_issues: vulnerability.issue_links.any? || vulnerability.external_issue_links.any?,
            has_merge_request: vulnerability.merge_request_links.any?
          }.merge!(@attributes)
        )
      end

      def log_batch(message, records)
        return if records.blank?

        records.group_by(&:project_id).each do |project_id, project_records|
          ::Gitlab::AppLogger.info(
            class: self.class.name,
            message: message,
            project_id: project_id,
            count: project_records.count
          )
        end
      end
    end
  end
end
