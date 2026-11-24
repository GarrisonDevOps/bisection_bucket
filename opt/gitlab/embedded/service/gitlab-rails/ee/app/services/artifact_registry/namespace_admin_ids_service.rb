# frozen_string_literal: true

module ArtifactRegistry
  # Reads who holds Artifact Admin on the organization's Artifact Registry
  # namespace. Shared by the last-admin guard and the role assignment
  # permissions, so both apply the same rule.
  class NamespaceAdminIdsService
    PAGE_SIZE = LookupRoleAssignmentsService::MAX_PAGE_SIZE
    # Past this many pages there are thousands of admins, so no single
    # change can remove the last one.
    MAX_PAGES = 5

    def initialize(current_user:, organization:, namespace_id:)
      @current_user = current_user
      @organization = organization
      @namespace_id = namespace_id
    end

    # On success, the payload holds the active organization members with
    # Artifact Admin as admin_ids, or many: true when there are too many to
    # page through.
    def execute
      ids = admin_ids
      return ids if ids.is_a?(ServiceResponse)

      ServiceResponse.success(payload: { admin_ids: active_member_ids(ids) })
    end

    private

    attr_reader :current_user, :organization, :namespace_id

    def admin_ids
      ids = Set.new
      page_token = nil

      MAX_PAGES.times do
        result = LookupRoleAssignmentsService.new(
          current_user: current_user,
          organization: organization,
          resource_ids: [namespace_id],
          roles: [:artifact_admin],
          page_size: PAGE_SIZE,
          page_after: page_token
        ).execute

        # Owners must be able to read the admins. If IAM denies one, fail
        # closed rather than let an owner remove the last admin unchecked.
        if result.reason == :permission_denied
          return current_user&.owns_organization?(organization) ? unknown_error : not_readable_error
        end

        return unknown_error if result.error?

        result.payload[:role_assignments].each do |assignment|
          local_id = assignment.subject.identity&.local_id
          ids << local_id.to_i if local_id.present?
        end

        page_token = result.payload[:next_page_token]
        return ids if page_token.blank?
      end

      ServiceResponse.success(payload: { many: true })
    end

    def unknown_error
      ServiceResponse.error(message: 'Could not read the Artifact Admins', reason: :unknown)
    end

    def not_readable_error
      ServiceResponse.error(message: 'Not allowed to read the Artifact Admins', reason: :not_readable)
    end

    # Leaving the organization does not delete IAM grants, and a blocked user
    # cannot act, so only active members count as admins.
    def active_member_ids(user_ids)
      member_ids = ::Organizations::OrganizationUser.member_ids_among(organization, user_ids.to_a)

      ::User.id_in(member_ids).active_without_ghosts.pluck_primary_key.to_set
    end
  end
end
