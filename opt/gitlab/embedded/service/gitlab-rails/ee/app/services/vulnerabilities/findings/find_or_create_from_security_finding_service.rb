# frozen_string_literal: true

module Vulnerabilities
  module Findings
    class FindOrCreateFromSecurityFindingService < ::BaseProjectService
      include ::Gitlab::Utils::StrongMemoize
      include ::VulnerabilityFindingHelpers

      def execute
        return ServiceResponse.error(message: _('Security Finding not found')) unless security_finding

        return ServiceResponse.error(message: _('Report Finding not found')) unless report_finding

        return tracked_context_result if tracked_contexts_enabled? && !tracked_context_result.success?

        unless vulnerability_finding.persisted?
          return ServiceResponse.error(message: vulnerability_finding_creation_error_msg)
        end

        ServiceResponse.success(payload: {
          vulnerability_finding: vulnerability_finding,
          security_finding: security_finding,
          merge_target_findings: merge_target_findings
        })
      end

      private

      def vulnerability_finding_creation_error_msg
        format(_("Error creating vulnerability finding: %{errors}"),
          errors: vulnerability_finding.errors.full_messages.join(', '))
      end

      def vulnerability_finding
        existing_finding = Vulnerabilities::Finding.by_uuid(params[:security_finding_uuid])&.first
        return existing_finding if existing_finding.present?

        create_finding(security_finding.uuid, tracked_contexts_enabled? ? tracked_context : nil)
      end
      strong_memoize_attr :vulnerability_finding

      # A finding triaged from a merge request is keyed by the UUID of the context it was
      # reported on, which the target branch never computes. Mirroring the record into the
      # target branch's context lets post-merge ingestion match it by UUID and promote the
      # existing vulnerability rather than opening a second one in the detected state.
      # Not gated on VAC: the UUID version comes from the target context, which can be v2 with VAC off.
      def merge_target_findings
        merge_target_contexts.filter_map { |context| mirror_finding_into(context) }
      end
      strong_memoize_attr :merge_target_findings

      def merge_target_contexts
        return [] unless pipeline

        target_branches = pipeline.all_merge_requests.map(&:target_branch).uniq
        return [] if target_branches.empty?

        ::Security::ProjectTrackedContext
          .for_project(project.id)
          .for_context_name(target_branches)
          .for_context_type(:branch)
          .tracked
          .to_a
      end

      def mirror_finding_into(tracked_context)
        uuid = uuid_for(tracked_context)
        return if uuid.blank? || uuid == vulnerability_finding.uuid

        existing_finding = Vulnerabilities::Finding.by_uuid(uuid).first
        return create_finding(uuid, tracked_context) unless existing_finding

        # An already ingested finding belongs to the target branch in its own right, so
        # leave it be: relinking it would move it onto the wrong vulnerability.
        existing_finding if existing_finding.vulnerability_id.nil?
      end

      def uuid_for(tracked_context)
        ::Security::VulnerabilityUUID.generate(
          report_type: report_finding.report_type,
          primary_identifier_fingerprint: report_finding.primary_identifier_fingerprint,
          location_fingerprint: report_finding.location_fingerprint,
          project_id: project.id,
          tracked_context: tracked_context
        )
      end

      def create_finding(uuid, tracked_context)
        finding = build_vulnerability_finding(security_finding)
        finding.uuid = uuid
        finding.security_project_tracked_context_id = tracked_context&.id

        Vulnerabilities::Finding.feature_flagged_transaction_for(@project) do
          save_identifiers(finding.identifiers)

          raise ActiveRecord::Rollback unless finding.save
        end

        finding
      end

      def save_identifiers(identifiers)
        return if identifiers.blank?

        sorted_identifiers = identifiers.sort_by(&:fingerprint)

        sorted_identifiers.each do |identifier|
          identifier.created_at = identifier.updated_at = Time.zone.now
        end

        identifier_ids = Vulnerabilities::Identifier.bulk_upsert!(
          sorted_identifiers,
          unique_by: %i[project_id fingerprint],
          returns: :id
        )

        identifier_ids.each_with_index do |id, index|
          sorted_identifiers[index].id = id
          # We need to mark the identifiers as persisted, otherwise ActiveRecord
          # will try to insert identifiers again while saving the finding object
          sorted_identifiers[index].instance_variable_set(:@new_record, false)
        end
      end

      def security_finding
        @security_finding ||= Security::Finding
          .with_pipeline_entities
          .latest_by_uuid(params[:security_finding_uuid])
      end

      def report_finding
        @report_finding ||= report_finding_for(security_finding)
      end

      def report_finding_for(security_finding)
        reports = security_finding.build.job_artifacts.filter_map(&:security_report)
        return unless reports.present?

        lookup_uuid = security_finding.overridden_uuid || security_finding.uuid

        reports.flat_map(&:findings).find { |finding| finding.uuid == lookup_uuid }
      end

      def pipeline
        security_finding.build.pipeline
      end

      def vulnerability_for(security_finding_uuid)
        project.vulnerabilities.with_findings_by_uuid(security_finding_uuid)&.first
      end

      def tracked_context_result
        ::Security::ProjectTrackedContexts::FindOrCreateService.from_pipeline(security_finding.pipeline,
          allow_untracked: true).execute
      end
      strong_memoize_attr :tracked_context_result

      def tracked_context
        tracked_context_result.payload[:tracked_context]
      end

      def tracked_contexts_enabled?
        Security::VAC.enabled?(project)
      end
      strong_memoize_attr :tracked_contexts_enabled?
    end
  end
end
