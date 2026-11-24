# frozen_string_literal: true

module MergeRequests
  class MergeAuditEventService
    attr_reader :merge_request

    def initialize(merge_request:)
      @merge_request = merge_request
    end

    def execute
      return unless merge_request.merged?

      audit_context = {
        name: 'merge_request_merged',
        author: merged_by,
        scope: merge_request.project,
        target: merge_request,
        message: 'Merge request merged',
        additional_details: audit_details,
        organization: merge_request.project.organization
      }

      ::Gitlab::Audit::Auditor.audit(audit_context)
      audit_merge_source
    end

    private

    def audit_merge_source
      merge_source = merge_request.merge_source
      return unless merge_source

      ::Gitlab::Audit::Auditor.audit({
        author: merged_by,
        scope: merge_request.project,
        target: merge_request,
        organization: merge_request.project.organization
      }.merge(merge_source_details(merge_source)))
    # A raise would retry the worker and audit merge_request_merged a second time
    rescue StandardError => e
      Gitlab::ErrorTracking.track_exception(e, merge_request_id: merge_request.id)
    end

    def merge_source_details(merge_source)
      if merge_source.source_commit
        {
          name: 'merge_request_merged_by_push',
          message: "Merge request merged by a push of commit #{Commit.truncate_sha(merge_source.source_commit)}",
          additional_details: { source_commit_sha: merge_source.source_commit }
        }
      else
        source_merge_request = merge_source.source_merge_request

        {
          name: 'merge_request_merged_through_merge_request',
          message: "Merge request merged through merge request #{source_merge_request.to_reference(full: true)}",
          additional_details: {
            source_merge_request_id: source_merge_request.id,
            source_merge_request_iid: source_merge_request.iid,
            source_project_id: source_merge_request.project_id
          }
        }
      end
    end

    def audit_details
      {
        title: merge_request.title,
        description: merge_request.description,
        required_approvals: required_approvals,
        approval_count: approval_count,
        approvers: approvers,
        approving_committers: approving_committers,
        approving_author: approving_author,
        merged_at: merged_at,
        commit_shas: commit_shas,
        target_branch: merge_request.target_branch,
        target_project_id: merge_request.target_project.id
      }
    end

    def approval_count
      merge_request.approvals.count
    end

    def approvers
      merge_request.approved_by_users.map(&:username).sort
    end

    def approving_committers
      approvers.select { |approver| approver.in? committers }
    end

    def committers
      # Use the approval filter's identity set so instance-signed web commits
      # report their Git author, which persisted diff commits cannot detect by signature.
      @committers ||= merge_request.committers_to_filter_from_approvers.map(&:username)
    end

    def author
      merge_request.author.username
    end

    def approving_author
      author.in? approvers
    end

    def merged_by
      merge_request.metrics.merged_by || Gitlab::Audit::DeletedAuthor.new(id: -3, name: 'Unknown User')
    end

    def merged_at
      merge_request.merged_at
    end

    def commit_shas
      merge_request.merge_request_diff&.commit_shas
    end

    def required_approvals
      merge_request.approvals_required
    end
  end
end
