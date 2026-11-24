# frozen_string_literal: true

module ArtifactRegistry
  class BaseService
    include ::Gitlab::Utils::StrongMemoize
    include ::Gitlab::InternalEventsTracking

    TOKEN_AUDIENCE = %w[gitlab-iam-data-access].freeze
    # Own-role reads run in Puma on page loads, so they get a shorter deadline than writes.
    READ_TIMEOUT_SECONDS = 5

    private

    attr_reader :current_user, :organization

    # Check organization membership, not ownership: users can belong to
    # several organizations. IAM also authorizes grant holders whose home
    # organization differs from the resource's organization.
    def caller_in_organization?
      current_user.member_of_organization?(organization)
    end

    # Only name a parent once AR confirms the resource is in this
    # organization's namespace: IAM trusts the parent Rails claims and cannot
    # check it. structural_ancestor_for only finds a candidate.
    def verified_ancestor_for(resource_id)
      ancestor = structural_ancestor_for(resource_id)
      return unless ancestor

      # Skips AR entirely when there is no ancestor to claim, so a request
      # naming only the namespace or the organization never calls out.
      return unless verified_repository_ids.include?(resource_id)

      ancestor
    end

    # The owner's organization_admin grant sits on the organization itself
    # and is irrevocable (ADR-021). A grant there would replace it, so grant
    # and revoke both refuse the organization's own resource.
    def organization_resource?(resource_id)
      resource_id == organization.uuid
    end

    # A repository's parent is the organization's AR namespace, so IAM honors
    # an admin role held there. The organization and namespace have no parent.
    # Structural only: verified_ancestor_for checks it before use.
    def structural_ancestor_for(resource_id)
      return if resource_id == organization.uuid
      return if resource_id == artifact_registry_namespace_id

      artifact_registry_namespace_id
    end

    # One batched call per request, regardless of size. What a failure means
    # is the subclass's call, so this defers to on_verification_failure
    # instead of deciding here.
    def verified_repository_ids
      candidate_repository_ids.to_set - verification_failures
    # ArgumentError because the client's own input guards raise it.
    rescue ::ArtifactRegistry::Client::Error, ArgumentError => e
      on_verification_failure(e)
    end
    strong_memoize_attr :verified_repository_ids

    # Raw on purpose. A verdict naming an id nobody submitted means AR is
    # confused, not that everything passed. Subtracting it from the
    # candidates would lose that distinction.
    def verification_failures
      return Set.new if candidate_repository_ids.empty?

      artifact_registry_client.verify_repositories(
        namespace_id: artifact_registry_namespace_id,
        repository_ids: candidate_repository_ids
      ).to_set
    end
    strong_memoize_attr :verification_failures

    def candidate_repository_ids
      namespace_id = artifact_registry_namespace_id
      return [] unless namespace_id

      submitted_resource_ids.uniq - [namespace_id, organization.uuid]
    end
    strong_memoize_attr :candidate_repository_ids

    # Grant fails closed here because writing an unverified resource
    # creates access. Revoke and lookup override this default because removing
    # or reading access must keep working even when AR cannot answer.
    def on_verification_failure(error)
      raise error
    end

    def submitted_resource_ids
      raise NotImplementedError, "#{self.class} must implement #submitted_resource_ids"
    end

    def artifact_registry_namespace_id
      organization.artifact_registry_namespace_mapping&.ar_namespace_id
    end
    strong_memoize_attr :artifact_registry_namespace_id

    def artifact_registry_client
      ::ArtifactRegistry::Client.new(current_user: current_user)
    end

    # IAM lets any caller read their own assignments, so this needs no grant.
    # One IAM call per user and organization per request. A failure raises and
    # is not cached, so each caller keeps its own failure policy.
    def own_namespace_role
      return unless artifact_registry_namespace_id

      ::Gitlab::SafeRequestStore.fetch([:artifact_registry_own_namespace_role, current_user.id, organization.id]) do
        relationships = ::Authn::IamService::LookupRelationshipsClient.new(timeout: READ_TIMEOUT_SECONDS).read(
          subject_id: current_user.id,
          organization_uuid: organization.uuid,
          objects: [artifact_registry_namespace_id],
          kinds: [LookupRoleAssignmentsService::ASSIGNMENT_KIND],
          token: token
        ).relationships

        # Roles::KEYS runs from least to most access, so several assignments resolve to the highest.
        relationships.filter_map { |relationship| Roles.name_for(relationship.role&.id) }
          .max_by { |role| Roles::KEYS.index(role) }
      end
    end

    def token
      ::Authn::TokenExchange::TokenIssuer.new(
        audiences: TOKEN_AUDIENCE,
        user: current_user,
        organization: organization
      ).token
    end

    # Return a bare error for one item; for bulk requests include the item's
    # position and resource so callers know which assignment to fix.
    # Subclasses provide request_items and position_error_format.
    def validation_error(errors)
      # Precondition, not a runtime case: every caller establishes that it has
      # something to report before formatting it. Named here so a future caller
      # that does not gets this rather than a nil dereference.
      raise ArgumentError, 'validation_error needs at least one error' if errors.empty?

      return errors.first[:message] if request_items.size == 1

      errors.map do |error|
        format(position_error_format, error.slice(:number, :resource_id, :message))
      end.join("\n")
    end

    # The client supplies failure reasons, while this service owns the
    # user-facing wording. Shared reasons live here; operation-specific
    # reasons live in the subclasses.
    def iam_error_message(reason)
      case reason
      when :unauthenticated
        s_('ArtifactRegistry|Could not authenticate with the Artifact Registry service.')
      when :unavailable
        s_('ArtifactRegistry|The Artifact Registry service is unavailable.')
      when :timeout
        s_('ArtifactRegistry|The Artifact Registry service did not respond in time.')
      else
        fallback_error_message(reason)
      end
    end

    def client
      raise NotImplementedError, "#{self.class} must implement #client"
    end

    def track_role_change(event_name, count)
      others = request_items.any? { |item| item[:assignee] != current_user }

      track_internal_event(
        event_name,
        user: current_user,
        additional_properties: { property: others ? 'other' : 'self', value: count }
      )
    end

    # IAM has already written, so an audit failure is reported, not returned.
    def audit_role_changes(event_name, items)
      scope = audit_scope
      namespace_details = { event_name: event_name, artifact_registry_namespace_id: artifact_registry_namespace_id }
      context = { name: event_name, author: current_user, scope: scope, target: ::Gitlab::Audit::NullTarget.new }

      ::Gitlab::Audit::Auditor.audit(context) do
        items.each do |item|
          attributes = yield(item)
          details = attributes.fetch(:additional_details, {}).merge(namespace_details)
          # A built event, not a hash, so the Auditor keeps composite-identity human author details.
          event = ::AuditEvents::BuildService.new(
            author: current_user, scope: scope, **attributes, additional_details: details
          ).execute

          ::Gitlab::Audit::EventQueue.push(event)
        end
      end
    rescue StandardError => e
      ::Gitlab::ErrorTracking.track_exception(e, event_name: event_name, organization_id: organization.id)
    end

    def audit_scope
      groups = TopLevelGroups.first_two(organization)

      groups.one? ? groups.first : ::Gitlab::Audit::InstanceScope.new
    end

    def error(message, reason: nil)
      ServiceResponse.error(message: message, reason: reason)
    end
  end
end
