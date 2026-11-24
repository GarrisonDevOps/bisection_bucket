# frozen_string_literal: true

module ArtifactRegistry
  module Resources
    class Namespaces < Base
      def namespace(uuid:)
        guard_segments!(uuid: uuid)

        # The caller looks up a UUID it persisted itself, so a 404 signals drift
        # between Rails and AR: worth logging for operators, but an expected nil
        # outcome for the caller rather than a raised error.
        nil_on_missing(log: true, uuid: uuid) do
          response = service_request(:get, namespace_path(uuid), uuid: uuid)
          attributes = success_body(response, expected: Hash, uuid: uuid)

          # Every reader would return nil, so a body without an id resolves to a
          # namespace that looks present: the opposite of what a drift check needs.
          raise_unexpected_success(response, uuid: uuid) if attributes['id'].blank?

          Namespace.new(attributes)
        end
      end

      def provision_namespace(slug:, platform:, entity_type:, entity_id:, billing_entity_type:, billing_entity_id:)
        guard_present!(slug: slug, platform: platform, entity_type: entity_type, entity_id: entity_id,
          billing_entity_type: billing_entity_type, billing_entity_id: billing_entity_id)
        guard_uuid!(entity_id: entity_id)

        # AR types every anchor field as a JSON string and its strict decoder
        # rejects a number, so billing_entity_id is coerced here: callers hold it
        # as the billing group's integer id.
        body = {
          slug: slug, platform: platform, entity_type: entity_type, entity_id: entity_id,
          billing_entity_type: billing_entity_type, billing_entity_id: billing_entity_id.to_s
        }

        # AR returns 201 on create and 200 on an exact-anchor replay; both carry
        # the namespace. The POST is never retried: a lost response would
        # double-apply provisioning, so recovery belongs to the calling service.
        response = service_request(:post, namespaces_path, body: body)
        attributes = success_body(response, expected: Hash)

        # A hollow namespace would be persisted as a valid mapping by the caller.
        raise_unexpected_success(response) if attributes['id'].blank?

        Namespace.new(attributes)
      end

      def disable_namespace(uuid:)
        namespace_condition(uuid, 'disable')
      end

      def enable_namespace(uuid:)
        namespace_condition(uuid, 'enable')
      end

      def namespace_details(slug:, include_permissions: false)
        guard_segments!(slug: slug)

        # Logged because this route needs no permission and is scoped to the caller's org, so a 404
        # means the slug or org has drifted, not that the caller simply lacks assignments.
        nil_on_missing(log: true, slug: slug) do
          response = user_request(:get, namespace_details_path(slug), slug: slug,
            query: permissions_query(include_permissions))
          attributes = success_body(response, expected: Hash, slug: slug)

          NamespaceDetails.new(attributes,
            verdicts(attributes['permissions'], scope: :namespace, read: :namespace_details, slug: slug,
              requested: include_permissions))
        end
      end

      def namespace_statistics(slug:)
        guard_segments!(slug: slug)

        path = namespace_statistics_path(slug)

        # path is logged so this read's 404 is distinguishable from the 404 the repositories list
        # logs for the same drifted slug; both otherwise log the bare origin alone.
        nil_on_missing(log: true, slug: slug, path: path) do
          response = user_request(:get, path, slug: slug)
          attributes = success_body(response, expected: Hash, slug: slug)

          raise_unexpected_success(response, slug: slug) if missing_expected_keys?(attributes, 'repositories_count',
            'deduplicated_size_bytes')

          NamespaceStatistics.new(attributes)
        end
      end

      # Batch repository membership check on the service-facing GitLab API surface: does every repository id belong to
      # the namespace? AR never says why an id failed, so an unknown id and one owned elsewhere are indistinguishable.
      # Any other failure raises, and the caller must fail closed: an outage is not a verdict.
      #
      # @param namespace_id [String] canonical lowercase UUID of the AR namespace
      # @param repository_ids [Array<String>] 1..1000 canonical lowercase UUIDv7s
      # @return [Array<String>] the submitted ids that failed verification ([] means the whole batch belongs)
      def verify_repositories(namespace_id:, repository_ids:)
        guard_verification_input!(namespace_id, repository_ids)

        response = service_request(:post, verifications_path(namespace_id),
          body: { repository_ids: repository_ids }, uuid: namespace_id)

        # The endpoint answers 204 and nothing else when every id belongs, so the status is the whole verdict and there
        # is no body to read. Another 2xx is contract drift rather than an answer, so refuse it instead of reading it as
        # an all-belong verdict.
        raise_unexpected_verification_status(response, namespace_id) unless response.status == 204

        []
      rescue ApiError => e
        raise unless e.status == 422

        verification_failure_ids(e, repository_ids)
      end

      private

      # Sends no body, not an empty object: AR's EmptyObject schema 400s any body
      # field, so sending nothing keeps a later argument from silently riding along.
      def namespace_condition(uuid, action)
        guard_segments!(uuid: uuid)

        response = service_request(:post, namespace_condition_path(uuid, action), uuid: uuid)
        attributes = success_body(response, expected: Hash, uuid: uuid)

        # A hollow namespace would read as a successful transition.
        raise_unexpected_success(response, uuid: uuid) if attributes['id'].blank?

        Namespace.new(attributes)
      end

      # A 422 echoes the failing ids under details['repository_ids'] (allowlisted by ErrorMapping); one that carries
      # none breaks that contract, so it is escalated as an unusable answer rather than a verdict. Held to the ids the
      # caller submitted, so a bug on the AR side cannot widen the verdict to a resource this request never named.
      # @see AR's VerificationFailure schema (api/openapi/gitlab-v1.yaml): failing ids deduplicated in submitted order
      def verification_failure_ids(error, submitted)
        details = error.details.is_a?(Hash) ? error.details['repository_ids'] : nil
        failing_ids = details.is_a?(Array) ? details & submitted : nil

        # An empty intersection is not "every id belongs": a 422 says at least one
        # failed, so a response naming none of the submitted ids is unreadable and
        # must not read as a pass.
        raise_unexpected_verification_failure(error) if failing_ids.blank?

        failing_ids
      end

      def raise_unexpected_verification_status(response, namespace_id)
        raise_terminal(
          UnavailableError,
          'Artifact Registry answered repository verification with an unexpected status',
          :post,
          status: response.status, uuid: namespace_id
        )
      end

      def raise_unexpected_verification_failure(error)
        raise_terminal(
          UnavailableError,
          'Artifact Registry returned an unreadable verification failure',
          :post,
          status: error.status, code: error.code, request_id: error.request_id
        )
      end
    end
  end
end
