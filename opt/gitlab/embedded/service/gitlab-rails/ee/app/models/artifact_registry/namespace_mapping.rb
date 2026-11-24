# frozen_string_literal: true

module ArtifactRegistry
  # Named NamespaceMapping, not Namespace, to avoid colliding with the
  # monolith/S02 client's ArtifactRegistry::Namespace value object: ee/lib and
  # ee/app/models share a Zeitwerk root, so both names resolve to one constant.
  class NamespaceMapping < ApplicationRecord
    self.table_name = 'artifact_registry_namespace_mappings'

    # Short expiries: a stale status only affects display, since the registry
    # enforces the real status on every request. A failure caches shorter so an
    # outage costs one call per organization per negative period, not one per render.
    CACHE_TTL = 5.minutes
    NEGATIVE_CACHE_TTL = 1.minute
    RACE_CONDITION_TTL = 10.seconds

    # A 404 keeps the row (the UUID was provisioned) but leaves the current
    # status unknowable, so it derives to this rather than to not-activated.
    UNKNOWN_STATUS = 'unknown'

    # The resolved namespace the render path reads. Every builder takes
    # ar_namespace_id from the mapping row rather than an Artifact Registry response,
    # so it is populated even when the resolution returned nothing.
    Registry = Struct.new(:ar_namespace_id, :slug, :status, :created_at, keyword_init: true) do
      def resolved?
        slug.present?
      end
    end

    # A resolution that failed, carrying the client error's detail so a consumer
    # can re-raise a faithful typed exception and map it the same way a live call
    # would, rather than after the cache flattened it.
    ResolutionFailure = Struct.new(:error_class, :status, :request_id, :code, :message, keyword_init: true) do
      def resolved?
        false
      end

      def to_client_error
        # error_class is always a Client::Error subclass name our own rescue wrote,
        # never user input; the hierarchy guard rejects anything else before use,
        # and an unrecognized name falls back to a loud unavailability.
        klass = error_class.safe_constantize
        klass = nil unless klass.is_a?(Class) && klass <= ::ArtifactRegistry::Client::Error
        klass ||= ::ArtifactRegistry::Client::UnavailableError

        attrs = { status: status, request_id: request_id }
        attrs[:code] = code if klass <= ::ArtifactRegistry::Client::ApiError

        klass.new(message, **attrs)
      end
    end

    belongs_to :organization, class_name: 'Organizations::Organization',
      inverse_of: :artifact_registry_namespace_mapping, optional: false

    validates :organization, uniqueness: true
    validates :ar_namespace_id, presence: true

    # The organizations this user is a member of that have Artifact Registry
    # set up. One row per organization, so the count is the number of such
    # organizations. The organization is preloaded because the join only
    # supports the where clause, so a caller reading .organization off each row
    # would otherwise issue a query per row.
    scope :for_member, ->(user) {
      joins(organization: :organization_users)
        .where(organization_users: { user_id: user.id })
        .preload(:organization)
    }

    scope :for_organization_id, ->(organization_id) { where(organization_id: organization_id) }

    # Returns a Registry on success or a ResolutionFailure on error. The failure
    # is a distinct value object, not nil, because callers must tell it apart
    # from a resolved registry after a cache read.
    def registry
      cached = Rails.cache.fetch(registry_cache_key, race_condition_ttl: RACE_CONDITION_TTL) do |_, options|
        resolve_registry(options)
      end

      build_registry(cached)
    end

    # touch moves the key (cache_key_with_version) so a read still in flight at Artifact
    # Registry writes its pre-transition answer where no later read looks. The delete
    # covers a reader that still loads the pre-touch row from a lagging replica.
    def expire_registry_cache
      previous_key = registry_cache_key
      touch
      Rails.cache.delete(previous_key)
    end

    private

    # Caches plain hashes rather than the value objects: a hash's marshalled
    # shape stays stable across code changes, so a rolling deploy that edits the
    # value objects cannot leave undeserializable entries behind.
    def resolve_registry(options)
      options.expires_in = CACHE_TTL
      namespace = organization.artifact_registry_service_client.namespace(uuid: ar_namespace_id)

      return { status: UNKNOWN_STATUS } if namespace.nil?

      # A recognized-or-not status passes through raw so the frontend's fallback,
      # not this code, handles an unrecognized value; a missing status resolves to
      # unknown rather than caching a nil the non-null GraphQL field cannot render.
      { slug: namespace.slug, status: namespace.status.presence || UNKNOWN_STATUS,
        created_at: namespace.created_at }
    rescue ::ArtifactRegistry::Client::Error => e
      options.expires_in = NEGATIVE_CACHE_TTL
      { error: { class: e.class.name, status: e.status, request_id: e.request_id,
                 code: (e.code if e.respond_to?(:code)), message: e.message } }
    end

    def build_registry(cached)
      error = cached[:error]
      return build_failure(error) if error

      Registry.new(ar_namespace_id: ar_namespace_id, slug: cached[:slug], status: cached[:status],
        created_at: cached[:created_at])
    end

    def build_failure(error)
      ResolutionFailure.new(
        error_class: error[:class], status: error[:status], request_id: error[:request_id],
        code: error[:code], message: error[:message]
      )
    end

    def registry_cache_key
      [cache_key_with_version, 'registry', 'v2']
    end
  end
end
