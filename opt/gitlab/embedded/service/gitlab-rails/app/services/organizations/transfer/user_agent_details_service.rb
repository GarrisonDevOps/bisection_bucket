# frozen_string_literal: true

module Organizations
  module Transfer
    class UserAgentDetailsService
      include Organizations::Transfer::Concerns::MissingRecordHandling

      ISSUE_BATCH_SIZE = 1_000
      SNIPPET_BATCH_SIZE = 1_000

      def initialize(group:, old_organization:, new_organization:)
        @group = group
        @old_organization = old_organization
        @new_organization = new_organization
      end

      def execute
        error = missing_record_error
        return error if error

        unless group.root?
          Gitlab::AppLogger.warn(
            message: 'Skipping user_agent_details transfer: group is not a root group',
            group_id: group.id
          )
          return ServiceResponse.error(message: 'Group is not a root group.', reason: :not_root_group)
        end

        transfer_issue_details
        transfer_project_snippet_details

        ServiceResponse.success
      end

      private

      attr_reader :group, :old_organization, :new_organization

      def transfer_issue_details
        Gitlab::Pagination::Keyset::Iterator
          .new(scope: hierarchy_issues)
          .each_batch(of: ISSUE_BATCH_SIZE) do |issues|
            transfer_details_for('Issue', issues.map(&:id))
          end
      end

      # rubocop:disable CodeReuse/ActiveRecord -- Keyset iteration needs this exact order with an id tie-breaker.
      def hierarchy_issues
        Issue
          .within_namespace_hierarchy(group)
          .select(:id, :created_at)
          .order(:created_at, :id)
      end
      # rubocop:enable CodeReuse/ActiveRecord

      def transfer_project_snippet_details
        Namespace.project_namespaces.by_root_id(group.id).each_batch do |namespaces|
          project_ids = Project.by_project_namespace(namespaces.select(:id)).pluck_primary_key
          next if project_ids.empty?

          Snippet.for_projects(project_ids).each_batch(of: SNIPPET_BATCH_SIZE) do |snippets|
            transfer_details_for('Snippet', snippets.select(:id))
          end
        end
      end

      def transfer_details_for(subject_type, subject_ids)
        UserAgentDetail
          .in_organization(old_organization)
          .for_subjects(subject_type, subject_ids)
          .update_all(organization_id: new_organization.id)
      end
    end
  end
end
