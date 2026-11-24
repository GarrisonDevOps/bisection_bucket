# frozen_string_literal: true

module ArtifactRegistry
  # Provisions an artifact registry namespace for an organization.
  #
  # The organization uniqueness constraint is the concurrency guard: a losing
  # racer's insert is rescued and resolved to the winning row, so two same-slug
  # requests produce one row and both succeed, and a same-handle repeat request is
  # idempotent.
  class ProvisionNamespaceService
    # service_credential stays mandatory: whatever the caller injects now travels
    # in the AR service-token header, so it must be the mounted secret.
    def initialize(organization:, slug:, service_credential:)
      @organization = organization
      @slug = slug.to_s
      @service_credential = service_credential
    end

    def execute
      existing = organization.artifact_registry_namespace_mapping
      return resolve_existing(existing) if existing

      validator = SlugValidator.new(slug)
      return validator.result unless validator.valid?

      billing_group = resolve_billing_group
      return billing_group unless billing_group.is_a?(::Group)
      return throttled_error if claim_throttled?

      provision(billing_group)
    end

    private

    attr_reader :organization, :slug, :service_credential

    # Compared against a live read, never mapping.registry: a cached handle must not decide a claim.
    def resolve_existing(mapping)
      namespace = client.namespace(uuid: mapping.ar_namespace_id)
      invalidate_registry_cache(mapping)
      return unresolvable_existing if namespace.nil?

      payload = { namespace_mapping: mapping, ar_namespace: namespace }
      return purged_existing if namespace.status == Namespace::PURGED_STATUS
      return ServiceResponse.success(payload: payload) if namespace.slug == slug

      ServiceResponse.error(
        message: format(
          s_("ArtifactRegistry|Artifact Registry is already activated for this organization with the handle " \
            "'%{handle}'."),
          handle: namespace.slug
        ),
        reason: :already_activated,
        payload: payload
      )
    rescue Client::UnavailableError => e
      ServiceResponse.error(message: e.message, reason: :service_unavailable)
    end

    # The mutation renders its own service-unavailable message, so this one is for the response only.
    def unresolvable_existing
      ServiceResponse.error(message: 'Artifact Registry no longer knows the mapped namespace',
        reason: :service_unavailable)
    end

    # The live read is fresher than whatever the render path cached; a cache failure
    # must not fail the claim, and a stale entry self-heals at the resolution TTL.
    def invalidate_registry_cache(mapping)
      mapping.expire_registry_cache
    rescue StandardError => e
      ::Gitlab::ErrorTracking.track_exception(e)
    end

    # Provisioning past a purged namespace would orphan the new one against the surviving mapping row.
    def purged_existing
      ServiceResponse.error(
        message: s_("ArtifactRegistry|This organization's Artifact Registry was purged. Setting up a new one is not " \
          "available yet."),
        reason: :reonboarding_unavailable
      )
    end

    def provision(billing_group)
      logger.info(**log_base_data.merge(message: 'provision_namespace request', slug: slug,
        Labkit::Fields::GL_ROOT_NAMESPACE_ID => billing_group.id))

      ar_namespace = client.provision_namespace(
        slug: slug,
        platform: Client::PLATFORM,
        entity_type: Client::ENTITY_TYPE_ORGANIZATION,
        entity_id: organization.uuid,
        billing_entity_type: Client::BILLING_ENTITY_TYPE_TOP_LEVEL_GROUP,
        billing_entity_id: billing_group.id
      )

      logger.info(**log_base_data.merge(message: 'provision_namespace response', ar_namespace_id: ar_namespace.id))

      mapping = create_or_resolve_mapping(ar_namespace.id)
      return mapping_lost_error if mapping.nil?

      # Hand back the namespace already fetched so the caller reads status and
      # created_at from it rather than a second GET on a cache the new row has
      # not warmed yet.
      ServiceResponse.success(payload: { namespace_mapping: mapping, ar_namespace: ar_namespace })
    rescue Client::ApiError => e
      handle_api_error(e)
    rescue Client::UnavailableError => e
      ServiceResponse.error(message: e.message, reason: :service_unavailable)
    end

    # A concurrent same-slug request can win the organization uniqueness guard
    # first: the validation raises RecordInvalid, the DB index raises
    # RecordNotUnique, and either way the winning row already holds the mapping.
    # Only that taken-organization case is resolved; any other invalidity (e.g. a
    # blank ar_namespace_id) is a real error and re-raises.
    def create_or_resolve_mapping(ar_namespace_id)
      NamespaceMapping.create!(organization: organization, ar_namespace_id: ar_namespace_id)
    rescue ActiveRecord::RecordNotUnique
      organization.reset.artifact_registry_namespace_mapping
    rescue ActiveRecord::RecordInvalid => e
      raise unless e.record.errors.of_kind?(:organization, :taken)

      organization.reset.artifact_registry_namespace_mapping
    end

    def resolve_billing_group
      top_level_groups = TopLevelGroups.first_two(organization)

      case top_level_groups.length
      when 0
        ServiceResponse.error(
          message: s_('ArtifactRegistry|Organization has no top-level groups.'),
          reason: :no_billing_anchor
        )
      when 1
        top_level_groups.first
      else
        ServiceResponse.error(
          message: s_('ArtifactRegistry|Organization has more than one top-level group.'),
          reason: :multiple_billing_anchors
        )
      end
    end

    # Counts the claim before its outcome is known, so claims AR refuses spend the limit too.
    def claim_throttled?
      ::Gitlab::ApplicationRateLimiter.throttled?(:artifact_registry_namespace_provisioning,
        scope: { organization: organization })
    end

    # Labkit's block metric carries no organization, so this line is what shows who was throttled.
    def throttled_error
      logger.warn(**log_base_data.merge(message: 'provision_namespace throttled', slug: slug))

      ServiceResponse.error(
        message: s_('ArtifactRegistry|Too many attempts to claim a handle. Try again later.'),
        reason: :rate_limited
      )
    end

    def mapping_lost_error
      ServiceResponse.error(
        message: s_('ArtifactRegistry|Namespace mapping was removed during a concurrent request.'),
        reason: :mapping_lost
      )
    end

    # AR's 409 and 422 text names the reason (taken, protocol-reserved, brand-reserved). ADR-015 keeps
    # it from the owner, so it goes to the log only. Anchor refusals share these codes until
    # https://gitlab.com/gitlab-org/ops/artifact-registry/-/work_items/1564 adds a reason.
    def handle_api_error(error)
      case error.status
      when 409
        log_refusal(error)
        ServiceResponse.error(message: availability_refusal_message, reason: :conflict)
      when 422
        log_refusal(error)
        ServiceResponse.error(message: availability_refusal_message, reason: :unprocessable)
      else
        ServiceResponse.error(message: error.message, reason: :api_error)
      end
    end

    def log_refusal(error)
      logger.warn(**log_base_data.merge(message: 'provision_namespace refused',
        Labkit::Fields::HTTP_STATUS_CODE => error.status, Labkit::Fields::ERROR_MESSAGE => error.message,
        code: error.code, request_id: error.request_id))
    end

    def availability_refusal_message
      s_('ArtifactRegistry|This handle is not available. Choose a different handle.')
    end

    def log_base_data
      {
        Labkit::Fields::CLASS_NAME => self.class.name,
        Labkit::Fields::GL_ORGANIZATION_ID => organization.id
      }
    end

    def client
      @client ||= Client.new(service_credential: service_credential)
    end

    def logger
      @logger ||= Logger.build
    end
  end
end
