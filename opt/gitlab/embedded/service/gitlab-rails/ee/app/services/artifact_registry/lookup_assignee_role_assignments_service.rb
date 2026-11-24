# frozen_string_literal: true

module ArtifactRegistry
  # IAM has no subject filter on LookupRelationships, so non-owners read per
  # repository. AR lists only the repositories a non-namespace-admin holds
  # grants on, so namespace admin is checked first to avoid a partial list.
  class LookupAssigneeRoleAssignmentsService < BaseService
    ASSIGNMENT_KIND = LookupRoleAssignmentsService::ASSIGNMENT_KIND
    IAM_PAGE_SIZE = LookupRoleAssignmentsService::MAX_PAGE_SIZE

    # Bounds the admin path, which reads every repository in the namespace.
    MAX_REPOSITORIES = 1_000
    REPOSITORY_PAGE_SIZE = 100
    # Bounds how many IAM pages one request may drain on either path.
    MAX_IAM_PAGES = 20

    LimitExceededError = Class.new(StandardError)

    def initialize(current_user:, organization:, assignee_ids:, roles: [])
      @current_user = current_user
      @organization = organization
      @assignee_ids = assignee_ids.map(&:to_s).uniq
      @roles = roles
    end

    def execute
      unless current_user
        return error(s_('ArtifactRegistry|You must be signed in to read role assignments.'), reason: :signed_out)
      end

      return error(s_('ArtifactRegistry|Organization could not be determined.')) unless organization
      return error(not_found_message, reason: :not_found) unless caller_in_organization?

      unknown_roles = role_ids.select { |_role, id| id.nil? }.keys
      return error(unknown_roles_message(unknown_roles), reason: :invalid_request) if unknown_roles.any?

      # Without a namespace there are no repositories to hold assignments.
      return success([]) if assignee_ids.empty? || artifact_registry_namespace_id.nil?

      role_assignments =
        if current_user.owns_organization?(organization)
          assignments_by_subject
        else
          assignments_by_repository
        end

      success(sorted(role_assignments))
    rescue ::Authn::IamService::LookupRelationshipsClient::RequestError => e
      error(iam_error_message(e.reason), reason: e.reason)
    rescue LimitExceededError => e
      error(e.message)
    rescue ::ArtifactRegistry::Client::Error
      error(s_('ArtifactRegistry|The Artifact Registry repositories could not be listed.'))
    end

    private

    attr_reader :assignee_ids, :roles

    def assignments_by_subject
      excluded_ids = [artifact_registry_namespace_id, organization.uuid]

      assignee_ids.flat_map { |assignee_id| subject_assignments(assignee_id) }
        .reject { |relationship| excluded_ids.include?(relationship.object&.id) }
    end

    def subject_assignments(assignee_id)
      drain do |page_token|
        client.lookup_resources(
          subject_id: assignee_id,
          organization_uuid: organization.uuid,
          kinds: [ASSIGNMENT_KIND],
          role_ids: role_ids.values,
          page_size: IAM_PAGE_SIZE,
          page_token: page_token,
          token: token
        )
      end
    rescue ::Authn::IamService::LookupRelationshipsClient::RequestError => e
      # IAM answers NOT_FOUND for a subject that has never held a relationship.
      raise unless e.reason == :not_found

      []
    end

    def assignments_by_repository
      authorize_namespace_admin!

      repository_ids = namespace_repository_ids
      return [] if repository_ids.empty?

      objects = repository_ids.map { |id| { id: id, ancestor_ids: [artifact_registry_namespace_id] } }

      relationships = drain do |page_token|
        client.lookup(
          objects: objects,
          kinds: [ASSIGNMENT_KIND],
          role_ids: role_ids.values,
          page_size: IAM_PAGE_SIZE,
          page_token: page_token,
          token: token
        )
      end

      relationships.select { |relationship| assignee_ids.include?(relationship.subject&.identity&.local_id) }
    end

    # With no ancestor named, IAM requires a direct admin grant on the
    # namespace itself and raises permission_denied otherwise.
    def authorize_namespace_admin!
      client.lookup(
        objects: [{ id: artifact_registry_namespace_id }],
        kinds: [ASSIGNMENT_KIND],
        role_ids: [],
        page_size: 1,
        page_token: nil,
        token: token
      )
    end

    # The ids come from Artifact Registry's own listing of this namespace,
    # which is what makes naming the namespace as their ancestor truthful.
    def namespace_repository_ids
      ar_client = organization.artifact_registry_client(current_user: current_user)
      ids = []
      cursor = nil

      # One page more than the cap needs, so a namespace over the cap is detected.
      ((MAX_REPOSITORIES / REPOSITORY_PAGE_SIZE) + 1).times do
        page = ar_client.repositories(slug: artifact_registry_slug, limit: REPOSITORY_PAGE_SIZE, cursor: cursor)
        # Artifact Registry hides a namespace the caller cannot see.
        raise_permission_denied unless page

        ids.concat(page.nodes.filter_map { |repository| repository.id&.downcase })
        raise_repository_limit if ids.size > MAX_REPOSITORIES

        cursor = page.next_cursor
        return ids.uniq if cursor.blank?
      end

      raise_repository_limit
    end

    def artifact_registry_slug
      registry = organization.artifact_registry_namespace_mapping.registry
      raise registry.to_client_error if registry.is_a?(::ArtifactRegistry::NamespaceMapping::ResolutionFailure)
      raise ::ArtifactRegistry::Client::Error, 'namespace slug unresolved' unless registry.resolved?

      registry.slug
    end
    strong_memoize_attr :artifact_registry_slug

    # Reads every page, failing rather than returning a partial list: a
    # caller revoking these grants must not miss any.
    def drain
      relationships = []
      page_token = nil

      MAX_IAM_PAGES.times do
        response = yield(page_token)
        relationships.concat(response.relationships.to_a)
        page_token = response.next_page_token.presence
        return relationships unless page_token
      end

      raise LimitExceededError, s_('ArtifactRegistry|Too many role assignments to look up by assignee.')
    end

    # Stable order, so the resolver's offset paging is consistent across calls.
    def sorted(relationships)
      relationships.sort_by do |relationship|
        [relationship.subject&.identity&.local_id.to_s, relationship.object&.id.to_s, relationship.role&.id.to_s]
      end
    end

    def role_ids
      roles.index_with do |role|
        ::Gitlab::Glaz.roles.find { |glaz_role| glaz_role[:key] == role.to_s.downcase }&.fetch(:id)
      end
    end
    strong_memoize_attr :role_ids

    def raise_permission_denied
      raise ::Authn::IamService::LookupRelationshipsClient::RequestError.new(
        'Artifact Registry namespace not visible to the caller', reason: :permission_denied
      )
    end

    def raise_repository_limit
      raise LimitExceededError, format(
        s_('ArtifactRegistry|Cannot look up role assignments by assignee in a namespace with more than ' \
          '%{limit} repositories.'),
        limit: MAX_REPOSITORIES
      )
    end

    def unknown_roles_message(unknown_roles)
      format(s_('ArtifactRegistry|Unknown roles: %{roles}.'), roles: unknown_roles.join(', '))
    end

    def client
      ::Authn::IamService::LookupRelationshipsClient.new
    end

    def success(role_assignments)
      ServiceResponse.success(payload: { role_assignments: role_assignments })
    end

    def fallback_error_message(reason)
      case reason
      when :permission_denied
        s_('ArtifactRegistry|You are not authorized to read these role assignments.')
      when :invalid_request
        s_('ArtifactRegistry|The role assignment lookup request was invalid.')
      when :not_found
        not_found_message
      else
        s_('ArtifactRegistry|The role assignment lookup could not be completed.')
      end
    end

    def not_found_message
      s_('ArtifactRegistry|The requested resources could not be found.')
    end
  end
end
