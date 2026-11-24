# frozen_string_literal: true

module ArtifactRegistry
  class Client < Resources::Base
    include Paths
    include Guards

    PAGINATION_RELS = %i[next prev].freeze

    KIND_HOSTED = 'hosted'
    KIND_REMOTE = 'remote'
    KIND_VIRTUAL = 'virtual'

    # Provisioning anchor tuple values. The client owns the wire contract, so
    # callers pass these through rather than defining their own.
    PLATFORM = 'gitlab'
    ENTITY_TYPE_ORGANIZATION = 'organization'
    BILLING_ENTITY_TYPE_TOP_LEVEL_GROUP = 'top_level_group'

    Error = Errors::Error
    AuthorizationError = Errors::AuthorizationError
    UnavailableError = Errors::UnavailableError
    ConfigurationError = Errors::ConfigurationError
    ApiError = Errors::ApiError

    def initialize(current_user: nil, organization: nil, base_url: nil, token_exchange: nil, service_credential: nil)
      api_url = base_url.presence || Configuration.api_url
      credential = service_credential || ServiceCredential.new

      reporting = Reporting.new(base_url: api_url, service_credential: credential)
      transport = Transport.new(
        base_url: api_url,
        current_user: current_user,
        organization: organization,
        token_exchange: token_exchange || TokenExchange.new,
        service_credential: credential,
        reporting: reporting
      )

      super(transport: transport, reporting: reporting)

      @artifacts = Resources::Artifacts.new(transport: transport, reporting: reporting)
      @upstreams = Resources::Upstreams.new(transport: transport, reporting: reporting)
      @namespaces = Resources::Namespaces.new(transport: transport, reporting: reporting)
    end

    def namespace(uuid:)
      @namespaces.namespace(uuid: uuid)
    end

    def provision_namespace(slug:, platform:, entity_type:, entity_id:, billing_entity_type:, billing_entity_id:)
      @namespaces.provision_namespace(slug: slug, platform: platform, entity_type: entity_type, entity_id: entity_id,
        billing_entity_type: billing_entity_type, billing_entity_id: billing_entity_id)
    end

    def disable_namespace(uuid:)
      @namespaces.disable_namespace(uuid: uuid)
    end

    def enable_namespace(uuid:)
      @namespaces.enable_namespace(uuid: uuid)
    end

    def namespace_details(slug:, include_permissions: false)
      @namespaces.namespace_details(slug: slug, include_permissions: include_permissions)
    end

    def repository(slug:, name:, include_permissions: false)
      guard_segments!(slug: slug, name: name)

      nil_on_missing do
        response = user_request(:get, repository_path(slug, name), slug: slug,
          query: permissions_query(include_permissions))
        attributes = success_body(response, expected: Hash, slug: slug)

        repository_with_verdicts(attributes, read: :repository, slug: slug, requested: include_permissions)
      end
    end

    def repositories(
      slug:, format: nil, kind: nil, sort: nil, order: nil, limit: nil, cursor: nil, include_permissions: false)
      guard_segments!(slug: slug)

      query = { format: format, kind: kind, sort: sort, order: order, limit: limit, cursor: cursor }.compact
        .merge(permissions_query(include_permissions))

      # Logged because an unreachable namespace can equally mean the slug this caller holds has
      # drifted from Artifact Registry's.
      nil_on_missing(log: true, slug: slug) do
        response = user_request(:get, repositories_path(slug), slug: slug, query: query)
        attributes_list, permissions = repository_list(response, slug: slug)

        cursors = link_cursors(response, slug: slug)

        Page.new(
          nodes: attributes_list.map do |attributes|
            repository_with_verdicts(attributes, read: :repositories, slug: slug, requested: include_permissions)
          end,
          next_cursor: cursors[:next],
          prev_cursor: cursors[:prev],
          permissions: verdicts(permissions, scope: :namespace, read: :repositories, slug: slug,
            requested: include_permissions)
        )
      end
    end

    def namespace_statistics(slug:)
      @namespaces.namespace_statistics(slug: slug)
    end

    def packages(slug:, repository_name:, format:, limit: nil, cursor: nil)
      guard_format!(format, Formats::PACKAGE_FORMATS)

      artifact_page(slug: slug, repository_name: repository_name, format: format, collection: 'packages',
        row_class: Formats.package_class(format), limit: limit, cursor: cursor)
    end

    def images(slug:, repository_name:, format:, limit: nil, cursor: nil)
      guard_format!(format, Formats::IMAGE_FORMATS)

      artifact_page(slug: slug, repository_name: repository_name, format: format, collection: 'images',
        row_class: Image, limit: limit, cursor: cursor)
    end

    def upstream_repositories(slug:, repository_name:, format:, include_permissions: false)
      @upstreams.upstream_repositories(slug: slug, repository_name: repository_name, format: format,
        include_permissions: include_permissions)
    end

    def package(slug:, repository_name:, format:, id:)
      guard_format!(format, Formats::PACKAGE_FORMATS)

      artifact(slug: slug, repository_name: repository_name, format: format, collection: 'packages',
        id: id, row_class: Formats.package_class(format))
    end

    def image(slug:, repository_name:, format:, id:)
      guard_format!(format, Formats::IMAGE_FORMATS)

      artifact(slug: slug, repository_name: repository_name, format: format, collection: 'images',
        id: id, row_class: Image)
    end

    def versions(slug:, repository_name:, format:, package_id:, sort: nil, order: nil, limit: nil, cursor: nil)
      guard_format!(format, Formats::PACKAGE_FORMATS)

      # package_id is guarded inside artifact_page (guard_segments!(id:) if sub_collection), the
      # single place every sub-collection read passes through.
      artifact_page(slug: slug, repository_name: repository_name, format: format, collection: 'packages',
        id: package_id, sub_collection: 'versions', row_class: Version,
        extra_query: { sort: sort, order: order }, limit: limit, cursor: cursor,
        log_context: { id: package_id })
    end

    def version(slug:, repository_name:, format:, version_id:)
      guard_format!(format, Formats::PACKAGE_FORMATS)

      # A blank or dot-segment version_id resolves nil here (the single-read guard, so a bad deep
      # link exposes no id-syntax oracle), unlike #version_files, whose sub-collection read raises.
      artifact(slug: slug, repository_name: repository_name, format: format, collection: 'versions',
        id: version_id, row_class: Version)
    end

    def version_statistics(slug:, repository_name:, format:, version_id:)
      guard_format!(format, Formats::PACKAGE_FORMATS)
      guard_segments!(slug: slug, repository_name: repository_name, version_id: version_id)

      path = sub_collection_path(slug, repository_name, format, 'versions', version_id, 'statistics')

      # 404 and 501 both mean no count available: the route exists before its handler, so an
      # unimplemented endpoint answers 501 rather than a real outage; both map to nil, not an error.
      # Note: 501 still emits one error-tracking event before the raise is swallowed.
      nil_on_missing do
        response = user_request(:get, path, slug: slug)

        VersionStatistics.new(success_body(response, expected: Hash, slug: slug))
      end
    rescue UnavailableError => e
      raise unless e.status == 501

      nil
    end

    # The path carries no format segment; format only picks the family count the 200 body must carry.
    # No 501 rescue, unlike version_statistics: this route shipped with its handler.
    def repository_statistics(slug:, repository_name:, format:)
      guard_format!(format, Formats::ARTIFACT_FORMATS)
      guard_segments!(slug: slug, repository_name: repository_name)

      path = repository_statistics_path(slug, repository_name)
      count_key = "#{Formats.collection(format)}_count"

      nil_on_missing do
        response = user_request(:get, path, slug: slug)
        attributes = success_body(response, expected: Hash, slug: slug)

        raise_unexpected_success(response, slug: slug) if missing_expected_keys?(attributes, count_key)

        RepositoryStatistics.new(attributes)
      end
    end

    def version_files(slug:, repository_name:, format:, version_id:, limit: nil, cursor: nil)
      guard_format!(format, Formats::PACKAGE_FORMATS)

      # version_id is guarded inside artifact_page (guard_segments!(id:) if sub_collection), the
      # single place every sub-collection read passes through. The endpoint sorts by file_name
      # alone, so no sort or order argument is forwarded.
      artifact_page(slug: slug, repository_name: repository_name, format: format, collection: 'versions',
        id: version_id, sub_collection: 'files', row_class: Formats.file_class(format),
        limit: limit, cursor: cursor, log_context: { id: version_id })
    end

    def npm_dist_tags(slug:, repository_name:, package_id:, limit: nil, cursor: nil)
      # Endpoint sorts by name only and its default order suits this read, so we forward no sort/order
      # arg even though it accepts one. Dist-tags are npm-only, so the format segment is hard-coded
      # 'npm' rather than a caller arg, which would expose an invalid surface for maven.
      artifact_page(slug: slug, repository_name: repository_name, format: 'npm', collection: 'packages',
        id: package_id, sub_collection: 'tags', row_class: NpmDistTag,
        limit: limit, cursor: cursor, log_context: { id: package_id })
    end

    # rubocop:disable Metrics/ParameterLists -- each keyword maps to a distinct AR contract argument
    def manifests(
      slug:, repository_name:, format:, image_id:,
      include_referrers: false, sort: nil, order: nil, limit: nil, cursor: nil)
      guard_format!(format, Formats::IMAGE_FORMATS)

      # image_id is guarded inside artifact_page (guard_segments!(id:) if sub_collection), the
      # single place every sub-collection read passes through. include_referrers is coerced so a
      # nil renders to false rather than a bare `?include_referrers=` that AR 400s, and a "false"
      # string reads as false rather than flipping referrers on.
      artifact_page(slug: slug, repository_name: repository_name, format: format, collection: 'images',
        id: image_id, sub_collection: 'manifests', row_class: Manifest,
        extra_query: { sort: sort, order: order,
                       include_referrers: Gitlab::Utils.to_boolean(include_referrers, default: false) },
        limit: limit, cursor: cursor, log_context: { id: image_id })
    end
    # rubocop:enable Metrics/ParameterLists

    def manifest(slug:, repository_name:, format:, image_id:, digest:)
      guard_format!(format, Formats::IMAGE_FORMATS)
      guard_segments!(slug: slug, repository_name: repository_name)
      return if malformed_deep_link?(image_id, digest)

      path = manifest_path(slug, repository_name, format, image_id, digest)

      # digest and media_type are contract-required, so a body lacking one fails loud here rather
      # than as a GraphQL non-null error on that field.
      read_resource(path, slug: slug, row_class: ManifestDetail, required_keys: %w[id digest media_type])
    end

    def manifest_referrers(slug:, repository_name:, format:, image_id:, digest:, limit: nil, cursor: nil)
      guard_format!(format, Formats::IMAGE_FORMATS)
      guard_segments!(slug: slug, repository_name: repository_name)
      return if malformed_deep_link?(image_id, digest)

      # The referrers list hangs off a single manifest, one segment deeper than a manifests list,
      # so it builds on the member path rather than through artifact_page's collection helper.
      # Every row is itself a manifest, so the list element is the same Manifest value object.
      path = "#{manifest_path(slug, repository_name, format, image_id, digest)}/referrers"

      query = { limit: limit, cursor: cursor }.compact

      # Log both the image id and the digest: the route is keyed on the pair, so a 404 is as likely
      # to be the drifted digest as the image id, and a log carrying only one cannot tell them apart.
      nil_on_missing(log: true, slug: slug, id: image_id, digest: digest) do
        response = user_request(:get, path, slug: slug, query: query)
        attributes_list = list_rows(response, slug: slug)

        cursors = link_cursors(response, slug: slug)

        Page.new(
          nodes: attributes_list.map { |attributes| Manifest.new(attributes) },
          next_cursor: cursors[:next],
          prev_cursor: cursors[:prev]
        )
      end
    end

    # Returns the stored payload as the bytes AR sent. Its encoding tag is whatever the transport set,
    # so a caller reading it as text checks those bytes itself.
    def manifest_payload(slug:, repository_name:, format:, image_id:, digest:)
      guard_format!(format, Formats::IMAGE_FORMATS)
      guard_segments!(slug: slug, repository_name: repository_name)
      return if malformed_deep_link?(image_id, digest)

      path = "#{manifest_path(slug, repository_name, format, image_id, digest)}/raw"

      # Logged, unlike the detail read's 404: this read is for a manifest already resolved, so a 404
      # means it went away between the reads or the deployment predates the raw route.
      nil_on_missing(log: true, slug: slug, id: image_id, digest: digest) do
        response = user_request(:get, path, slug: slug)
        payload = success_body(response, expected: String, slug: slug)

        # A JSON string decodes to a String too, so the class alone cannot tell a parsed body from a
        # payload. An empty body is no payload but a whitespace one is, hence empty? rather than blank?.
        raise_unexpected_success(response, slug: slug) if parsed_as_json?(response) || payload.empty?

        payload
      end
    end

    def create_repository(
      slug:, name:, format:, kind: nil, visibility: nil, description: nil, settings: nil,
      upstream_repository_ids: nil
    )
      guard_segments!(slug: slug, name: name)
      guard_present!(format: format)
      raise ArgumentError, 'settings is only accepted for a remote repository' if settings && kind != KIND_REMOTE
      raise ArgumentError, 'settings is required for a remote repository' if kind == KIND_REMOTE && settings.nil?

      if upstream_repository_ids && kind != KIND_VIRTUAL
        raise ArgumentError, 'upstream_repository_ids is only accepted for a virtual repository'
      end

      body = { name: name, format: format, kind: kind, visibility: visibility, description: description,
               settings: settings, upstream_repository_ids: upstream_repository_ids }.compact
      response = user_request(:post, repositories_path(slug), slug: slug, body: body)

      Repository.new(success_body(response, expected: Hash, slug: slug))
    end

    def update_repository(
      slug:, name:, visibility: NOT_PROVIDED, description: NOT_PROVIDED, settings: NOT_PROVIDED,
      upstream_repository_ids: NOT_PROVIDED
    )
      guard_segments!(slug: slug, name: name)
      raise ArgumentError, 'settings must not be nil' if settings.nil?
      raise ArgumentError, 'upstream_repository_ids must not be nil' if upstream_repository_ids.nil?

      body = provided_fields(visibility: visibility, description: description, settings: settings,
        upstream_repository_ids: upstream_repository_ids)
      raise ArgumentError, 'at least one mutable field is required' if body.empty?

      response = user_request(:patch, repository_path(slug, name), slug: slug, body: body)

      Repository.new(success_body(response, expected: Hash, slug: slug))
    end

    def delete_repository(slug:, name:)
      guard_segments!(slug: slug, name: name)

      response = user_request(:delete, repository_path(slug, name), slug: slug, query: { destructive: true })

      raise_unexpected_success(response, slug: slug) unless [202, 204].include?(response.status)

      true
    rescue ApiError => e
      return true if e.status == 404 && e.code == 'not_found'

      log_error(e, method: :delete, code: e.code, slug: slug) if e.status == 400

      raise
    end

    def bulk_delete_artifacts(slug:, repository_name:, format:)
      @artifacts.bulk_delete_artifacts(slug: slug, repository_name: repository_name, format: format)
    end

    # @return [void]
    def delete_manifest(slug:, repository_name:, format:, image_id:, digest:)
      guard_format!(format, Formats::IMAGE_FORMATS)
      guard_segments!(slug: slug, repository_name: repository_name, image_id: image_id, digest: digest)

      path = manifest_path(slug, repository_name, format, image_id, digest)

      response = user_request(:delete, path, slug: slug)

      raise_unexpected_success(response, slug: slug) unless response.status == 202

      nil
    end

    # @return [void]
    def delete_container_tag(slug:, repository_name:, format:, image_id:, tag_name:)
      guard_format!(format, Formats::IMAGE_FORMATS)
      guard_segments!(slug: slug, repository_name: repository_name, image_id: image_id, tag_name: tag_name)

      path = sub_collection_member_path(slug, repository_name, format, 'images', image_id, 'tags', tag_name)

      response = user_request(:delete, path, slug: slug)

      raise_unexpected_success(response, slug: slug) unless response.status == 202

      nil
    end

    def delete_artifact(slug:, repository_name:, format:, id:)
      @artifacts.delete_artifact(slug: slug, repository_name: repository_name, format: format, id: id)
    end

    # Inherits Transport::RETRY_OPTIONS' connection-wide :delete exclusion, so the DELETE is not replayed
    # onto the row a first attempt already removed.
    #
    # @return [void]
    def delete_version(slug:, repository_name:, format:, version_id:)
      guard_format!(format, Formats::PACKAGE_FORMATS)
      guard_segments!(slug: slug, repository_name: repository_name, version_id: version_id)

      path = artifact_path(slug, repository_name, format, 'versions', version_id)

      response = user_request(:delete, path, slug: slug)

      raise_unexpected_success(response, slug: slug) unless response.status == 202

      nil
    end

    # @return [void]
    def delete_npm_dist_tag(slug:, repository_name:, tag_id:)
      guard_segments!(slug: slug, repository_name: repository_name, tag_id: tag_id)

      path = artifact_path(slug, repository_name, 'npm', 'tags', tag_id)

      response = user_request(:delete, path, slug: slug)

      raise_unexpected_success(response, slug: slug) unless response.status == 202

      nil
    end

    # Sends the subset branch only: the whole-collection delete_all branch has no caller or
    # confirmation design. POST is outside RETRY_OPTIONS[:methods], so no batch is replayed.
    #
    # @param version_ids [Array<String>] the versions to delete, 1 to MAX_BULK_DELETE_BATCH entries
    # @return [void]
    def bulk_delete_versions(slug:, repository_name:, format:, package_id:, version_ids:)
      guard_format!(format, Formats::PACKAGE_FORMATS)
      guard_segments!(slug: slug, repository_name: repository_name, package_id: package_id)

      guard_batch!(:version_ids, version_ids, MAX_BULK_DELETE_BATCH)

      path = nested_bulk_delete_path(slug, repository_name, format, 'packages', package_id, 'versions')

      response = user_request(:post, path, slug: slug, body: { version_ids: version_ids })

      raise_unexpected_success(response, slug: slug) unless response.status == 202

      nil
    end

    # AR skips a listed manifest that an index outside the batch still references, without
    # reporting it, so a 202 does not mean every listed manifest is gone.
    #
    # @param digests [Array<String>] the manifest digests to delete, 1 to MAX_BULK_DELETE_BATCH entries
    # @return [void]
    def bulk_delete_manifests(slug:, repository_name:, format:, image_id:, digests:)
      guard_format!(format, Formats::IMAGE_FORMATS)
      guard_segments!(slug: slug, repository_name: repository_name, image_id: image_id)

      guard_batch!(:digests, digests, MAX_BULK_DELETE_BATCH)

      path = nested_bulk_delete_path(slug, repository_name, format, 'images', image_id, 'manifests')

      response = user_request(:post, path, slug: slug, body: { digests: digests })

      raise_unexpected_success(response, slug: slug) unless response.status == 202

      nil
    end

    def dissociate_upstream_repository(slug:, repository_name:, format:, association_id:)
      @upstreams.dissociate_upstream_repository(slug: slug, repository_name: repository_name, format: format,
        association_id: association_id)
    end

    def test_upstream_connection(slug:, name:)
      @upstreams.test_upstream_connection(slug: slug, name: name)
    end

    def test_namespace_upstream_connection(slug:, format:, url:, credentials: nil)
      @upstreams.test_namespace_upstream_connection(slug: slug, format: format, url: url, credentials: credentials)
    end

    def verify_repositories(namespace_id:, repository_ids:)
      @namespaces.verify_repositories(namespace_id: namespace_id, repository_ids: repository_ids)
    end

    private

    def artifact(slug:, repository_name:, format:, collection:, id:, row_class:)
      guard_segments!(slug: slug, repository_name: repository_name)
      return if malformed_deep_link?(id)

      path = artifact_path(slug, repository_name, format, collection, id)

      read_resource(path, slug: slug, row_class: row_class, required_keys: %w[id])
    end

    # A 404 is the ordinary miss for a user-supplied deep link, so it resolves nil unlogged.
    def read_resource(path, slug:, row_class:, required_keys:)
      nil_on_missing do
        response = user_request(:get, path, slug: slug)
        attributes = success_body(response, expected: Hash, slug: slug)

        raise_unexpected_success(response, slug: slug) if blank_required_keys?(attributes, *required_keys)

        row_class.new(attributes)
      end
    end

    # rubocop:disable Metrics/ParameterLists -- one shared reader for every keyset list; each keyword names a distinct part of the request
    def artifact_page(
      slug:, repository_name:, format:, collection:, row_class:, limit:, cursor:,
      id: nil, sub_collection: nil, extra_query: {}, log_context: {})
      guard_segments!(slug: slug, repository_name: repository_name)
      # A sub-collection read needs its parent id, so guard it here rather than trust each caller:
      # without this an id-less call would silently build a `.../packages//versions` path.
      guard_segments!(id: id) if sub_collection

      query = extra_query.merge(limit: limit, cursor: cursor).compact
      path =
        if sub_collection
          sub_collection_path(slug, repository_name, format, collection, id, sub_collection)
        else
          artifacts_path(slug, repository_name, format, collection)
        end

      nil_on_missing(log: true, slug: slug, **log_context) do
        response = user_request(:get, path, slug: slug, query: query)
        attributes_list = list_rows(response, slug: slug)

        cursors = link_cursors(response, slug: slug)

        Page.new(
          nodes: attributes_list.map { |attributes| row_class.new(attributes) },
          next_cursor: cursors[:next],
          prev_cursor: cursors[:prev]
        )
      end
    end
    # rubocop:enable Metrics/ParameterLists

    # `repositories` is always an array, `[]` when empty, so a missing key and a
    # value that is not an array of objects both violate the contract, and
    # list_class is what tells those two apart once body_class reports Hash.
    def repository_list(response, slug:)
      body = success_body(response, expected: Hash, slug: slug)
      list = body['repositories']

      unless list.is_a?(Array) && list.all?(Hash)
        raise_unexpected_success(response, slug: slug, list_class: list.class.name)
      end

      [list, body['permissions']]
    end

    def repository_with_verdicts(attributes, read:, slug:, requested:)
      Repository.new(attributes,
        verdicts(attributes['permissions'], scope: :repository, read: read, slug: slug, requested: requested))
    end

    def blank_required_keys?(attributes, *required_keys)
      required_keys.any? { |key| attributes[key].blank? }
    end

    # Mirrors the connection's JSON middleware match, an exact comparison of the media type before any
    # parameter, so it flags exactly the responses the connection parsed.
    def parsed_as_json?(response)
      response.headers['Content-Type'].to_s.split(';', 2).first == Transport::JSON_CONTENT_TYPE
    end

    def link_cursors(response, slug:)
      header = response.headers['Link']
      links = Gitlab::Utils::LinkHeaderParser.new(header).parse

      # Reading the header rather than each URI keeps the last page quiet: it still carries rel="prev".
      if header.present? && !links.keys.intersect?(PAGINATION_RELS)
        log_error(Error.new('Artifact Registry Link header yielded no usable rels'), slug: slug)
      end

      PAGINATION_RELS.index_with { |direction| link_cursor(links.dig(direction, :uri), direction, slug: slug) }
    rescue URI::InvalidURIError => e
      log_error(e, slug: slug)
      PAGINATION_RELS.index_with(nil)
    end

    def link_cursor(uri, direction, slug:)
      return unless uri

      cursor = Rack::Utils.parse_query(uri.query)['cursor']
      return cursor if cursor.present?

      log_error(Error.new("Artifact Registry #{direction} link carries no cursor"), slug: slug)
      nil
    end
  end
end
