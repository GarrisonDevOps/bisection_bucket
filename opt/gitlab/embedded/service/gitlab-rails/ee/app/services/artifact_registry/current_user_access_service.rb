# frozen_string_literal: true

module ArtifactRegistry
  # Answers what access the current user keeps on a repository without their
  # direct role there: the role they hold on the organization's Artifact
  # Registry namespace, and organization ownership.
  class CurrentUserAccessService < BaseService
    def initialize(current_user:, organization:)
      @current_user = current_user
      @organization = organization
    end

    def execute
      unless current_user
        return error(s_('ArtifactRegistry|You must be signed in to read role assignments.'), reason: :signed_out)
      end

      return error(s_('ArtifactRegistry|Organization could not be determined.')) unless organization
      return error(not_found_message, reason: :not_found) unless caller_in_organization?

      inherited_role = own_namespace_role
      namespace_admin = inherited_role == :artifact_admin
      # IAM admits an organization owner with no stored assignment, from the
      # same ownership check the token's `owner` claim is set from.
      owner = current_user.owns_organization?(organization)

      ServiceResponse.success(payload: {
        inherited_role: inherited_role,
        retains_access: owner || inherited_role.present?,
        remains_admin: owner || namespace_admin,
        can_read_inherited_roles: owner || namespace_admin
      })
    rescue ::Authn::IamService::LookupRelationshipsClient::RequestError => e
      error(iam_error_message(e.reason), reason: e.reason)
    rescue StandardError => e
      # A token failure raises before the client can report it.
      Gitlab::ErrorTracking.track_exception(e)
      error(iam_error_message(:unavailable), reason: :unavailable)
    end

    private

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

    def not_found_message
      s_('ArtifactRegistry|The requested resources could not be found.')
    end
  end
end
