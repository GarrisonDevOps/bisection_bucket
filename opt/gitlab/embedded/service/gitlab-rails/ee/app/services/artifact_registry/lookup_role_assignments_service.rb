# frozen_string_literal: true

module ArtifactRegistry
  # Reads Artifact Registry role assignments from the IAM Relationships API
  # (lookup.v1.LookupService#LookupRelationships).
  #
  # Validates the caller and the query inputs, then reads through IAM. IAM
  # enforces authorization itself: with no resources the caller must own the
  # organization; with resources the caller needs an admin grant on each one
  # or on its ancestor. Ancestors come only from AR verification, never from
  # the caller. This service performs no authorization of its own, the same
  # posture as GrantRoleAssignmentsService on the write path.
  class LookupRoleAssignmentsService < BaseService
    # IAM clamps page_size to its own cap; we clamp here too so a caller gets a
    # predictable bound rather than silent server-side truncation.
    MAX_PAGE_SIZE = 999

    # This endpoint reads role assignments. The relationships store is a
    # general tuple table that will hold other kinds (parent, seal, visibility)
    # as they land, so every read is scoped to the assignment kind rather than
    # returning whatever is stored. A general relationship read, if it is ever
    # needed, would be a separate API, not a kind filter added here. See the
    # discussion on https://gitlab.com/gitlab-org/gitlab/-/merge_requests/247150.
    ASSIGNMENT_KIND = :KIND_ASSIGNMENT

    def initialize(current_user:, organization:, resource_ids: [], roles: [], page_size: nil, page_after: nil)
      @current_user = current_user
      @organization = organization
      # IAM only accepts canonical lowercase ids, so normalize case here
      # rather than rejecting an uppercase id.
      @resource_ids = resource_ids.map { |resource_id| resource_id&.downcase }
      @roles = roles
      @page_size = page_size
      @page_after = page_after
    end

    def execute
      unless current_user
        return error(s_('ArtifactRegistry|You must be signed in to read role assignments.'), reason: :signed_out)
      end

      return error(s_('ArtifactRegistry|Organization could not be determined.')) unless organization
      # The IAM request carries no organization; the token scopes it. The
      # generic not-found message never discloses that another organization exists.
      return error(not_found_message, reason: :not_found) unless caller_in_organization?

      validation_message = inputs_error
      return error(validation_message, reason: :invalid_request) if validation_message

      response = client.lookup(
        objects: object_inputs,
        kinds: [ASSIGNMENT_KIND],
        role_ids: role_id_filters,
        page_size: clamped_page_size,
        page_token: page_after,
        token: token
      )

      ServiceResponse.success(payload: {
        role_assignments: response.relationships.to_a,
        next_page_token: response.next_page_token
      })
    rescue ::Authn::IamService::LookupRelationshipsClient::RequestError => e
      # Without the ancestor AR could not confirm, IAM may refuse a namespace
      # admin, so that refusal is an outage rather than a denial.
      reason = e.reason == :permission_denied && @verification_failed ? :unavailable : e.reason
      error(iam_error_message(reason), reason: reason)
    end

    private

    attr_reader :resource_ids, :roles, :page_size, :page_after

    alias_method :submitted_resource_ids, :resource_ids

    def inputs_error
      object_error || role_error
    end

    def object_error
      return if resource_ids.all? { |resource_id| ::Gitlab::UUID.v7?(resource_id) }

      s_('ArtifactRegistry|Resource ID must be a valid UUIDv7.')
    end

    def role_error
      unknown = resolved_roles.select { |_role, id| id.nil? }.keys
      return if unknown.empty?

      format(s_('ArtifactRegistry|Unknown roles: %{roles}.'), roles: unknown.join(', '))
    end

    # Resolves each requested role name to its id once, so validation and the
    # filter share a single pass. A nil id means the name is unknown.
    def resolved_roles
      @resolved_roles ||= roles.index_with do |role|
        ::Gitlab::Glaz.roles.find { |glaz_role| glaz_role[:key] == role.to_s.downcase }&.fetch(:id)
      end
    end

    def object_inputs
      resource_ids.map do |resource_id|
        { id: resource_id, ancestor_ids: Array(verified_ancestor_for(resource_id)) }
      end
    end

    # A read must keep answering while AR is down, so a failure names no
    # ancestor and IAM still answers for whatever the caller holds directly.
    def on_verification_failure(error)
      Gitlab::ErrorTracking.track_exception(
        error, organization_id: organization.id, ar_namespace_id: artifact_registry_namespace_id
      )
      @verification_failed = true
      Set.new
    end

    def role_id_filters
      resolved_roles.values.compact
    end

    # nil lets IAM apply its own default; a positive request is capped at
    # MAX_PAGE_SIZE; a non-positive request falls back to the default.
    def clamped_page_size
      return unless page_size
      return if page_size <= 0

      [page_size, MAX_PAGE_SIZE].min
    end

    def client
      ::Authn::IamService::LookupRelationshipsClient.new
    end

    def fallback_error_message(reason)
      case reason
      when :not_found
        not_found_message
      when :permission_denied
        s_('ArtifactRegistry|You are not authorized to read these role assignments.')
      when :invalid_request
        s_('ArtifactRegistry|The role assignment lookup request was invalid.')
      else
        s_('ArtifactRegistry|The role assignment lookup could not be completed.')
      end
    end

    # A generic message shared by the cross-organization guard and the IAM
    # not-found reason, so neither discloses whether a resource or org exists.
    def not_found_message
      s_('ArtifactRegistry|The requested resources could not be found.')
    end
  end
end
