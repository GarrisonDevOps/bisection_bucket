# frozen_string_literal: true

module Import
  module Sync
    module Github
      module Oauth
        # Verifies and deduplicates an incoming GitHub OAuth webhook delivery, then
        # schedules the reconcile domains the event can change. Review comment deletions
        # are removed in the background. Unsubscribed events are only logged.
        class WebhookReceiverService
          include ::Gitlab::Utils::Executable

          NotFoundError = Class.new(StandardError)
          BadRequestError = Class.new(StandardError)
          RateLimitedError = Class.new(StandardError)

          RATE_LIMIT_KEY = :github_oauth_webhook_delivery

          DELIVERY_HEADER = 'X-GitHub-Delivery'
          SIGNATURE_HEADER = 'X-Hub-Signature-256'
          EVENT_HEADER = 'X-GitHub-Event'
          DELIVERY_DEDUP_TTL = 10.minutes.to_i
          # `create` and `delete` are not subscribed because `push` already covers branch and tag creation and deletion.
          RECONCILE_DOMAINS = {
            'push' => %w[source],
            'repository' => %w[inventory],
            'issues' => %w[work_items],
            'issue_comment' => %w[work_items],
            'pull_request' => %w[work_items],
            'pull_request_review_comment' => %w[work_items],
            'pull_request_review' => %w[work_items],
            'release' => %w[work_items]
          }.freeze
          # Matches the cap Gitlab::Middleware::JsonValidation enforces for this route.
          # Kept here too as a backstop in case that route config ever drifts; read_body!
          # applies it before any project-specific check, so it can't become a way to
          # probe which projects have GitHub sync configured.
          MAX_PAYLOAD_BYTES = 25.megabytes

          def initialize(project, request:)
            @project = project
            @request = request
          end

          def execute
            response = receive_delivery
            count_delivery(response.success? ? :success : response.reason)
            response
          rescue StandardError
            count_delivery(:error)
            raise
          end

          private

          def receive_delivery
            verify_and_process!

            ServiceResponse.success
          rescue NotFoundError
            ServiceResponse.error(message: 'Not found', reason: :not_found)
          rescue BadRequestError => e
            ServiceResponse.error(message: e.message, reason: :bad_request)
          rescue RateLimitedError
            ServiceResponse.error(message: ::Gitlab::ApplicationRateLimiter.throttled_error_message,
              reason: :rate_limited)
          end

          def count_delivery(result)
            ::Gitlab::Metrics.counter(
              :gitlab_import_sync_webhook_deliveries_total,
              'Number of GitHub continuous sync webhook deliveries received, by result'
            ).increment(result: result.to_s)
          end

          attr_reader :project, :request

          def verify_and_process!
            body = read_body!

            raise NotFoundError unless repository && repository.webhook_secret.present?
            raise NotFoundError unless valid_signature?(body)
            raise RateLimitedError if rate_limited?

            delivery_id = headers[DELIVERY_HEADER]
            raise BadRequestError, 'Missing delivery id' if delivery_id.blank?

            payload = parse_body!(body)

            process_verified_delivery!(delivery_id, payload)
          end

          def repository
            @repository ||= project.import_sync_repository
          end

          # Checked only after the signature is verified, so an unsigned
          # request can never burn a project's budget.
          def rate_limited?
            ::Gitlab::ApplicationRateLimiter.throttled_request?(
              request, nil, RATE_LIMIT_KEY, scope: { project: project }
            )
          end

          def headers
            @headers ||= request.headers
          end

          def read_body!
            request.body.rewind
            body = request.body.read(MAX_PAYLOAD_BYTES + 1) || ''

            raise BadRequestError, 'Request body too large' if body.bytesize > MAX_PAYLOAD_BYTES

            body
          end

          def valid_signature?(body)
            signature = headers[SIGNATURE_HEADER]
            return false if signature.blank?

            digest = OpenSSL::HMAC.hexdigest('sha256', repository.webhook_secret, body)

            ActiveSupport::SecurityUtils.secure_compare(signature, "sha256=#{digest}")
          end

          def parse_body!(body)
            ::Gitlab::Json::SafeParser.parse(body, max_json_size_bytes: MAX_PAYLOAD_BYTES)
          rescue JSON::ParserError => e
            raise BadRequestError, e.message
          end

          # Deliveries are keyed by GitHub's own delivery id, scoped to the
          # repository, so a redelivery of the same event within the TTL is a
          # no-op rather than processed twice. The lease is only taken once the
          # delivery is verified and parsed, and is released if processing
          # raises, so a failed delivery can still be retried by GitHub.
          def process_verified_delivery!(delivery_id, payload)
            return if repository.disconnected?

            lease = acquire_delivery_lease(delivery_id)
            return unless lease

            begin
              log_received(payload)
              remove_deleted_review_comment(payload)
              schedule_reconcile
            rescue StandardError
              lease.cancel
              raise
            end
          end

          # Enqueued inside the lease so a redelivery of the same id never schedules twice.
          # Skipped unless GitHub is the active authority, since ScheduleReconcileService raises otherwise.
          def schedule_reconcile
            domains = RECONCILE_DOMAINS[headers[EVENT_HEADER]]
            return unless domains
            return unless repository.provisioning? || repository.provider_canonical?

            response = ::Import::Sync::Repositories::ScheduleReconcileService
              .new(repository, domains: domains, event_at: Time.current).execute

            ::Import::Sync::Repositories::ReconcileWorker
              .perform_async(repository.id, response.payload[:application_generation])
          rescue ::Import::Sync::Errors::InactiveAuthorityError
            # A stop that raced past the pre-check above: nothing to reconcile, so don't fail the delivery.
          end

          def acquire_delivery_lease(delivery_id)
            lease = ::Gitlab::ExclusiveLease.new(
              "import_sync:github_oauth_webhook_delivery:#{repository.id}:#{delivery_id}",
              timeout: DELIVERY_DEDUP_TTL
            )

            lease if lease.try_obtain
          end

          def remove_deleted_review_comment(payload)
            return unless headers[EVENT_HEADER] == 'pull_request_review_comment'
            return unless payload.is_a?(Hash) && payload['action'] == 'deleted'

            comment_id = payload.dig('comment', 'id')
            return unless comment_id.is_a?(Integer) && comment_id > 0

            ::Import::Sync::Repositories::RemoveDeletedReviewCommentWorker.perform_async(repository.id, comment_id)
          end

          def log_received(payload)
            ::Gitlab::GithubImport::Logger.info(
              Labkit::Fields::LOG_MESSAGE => 'Received GitHub OAuth webhook delivery',
              Labkit::Fields::GL_PROJECT_ID => repository.project_id,
              'import_sync_repository_id' => repository.id,
              'github_event' => headers[EVENT_HEADER],
              'github_action' => payload.is_a?(Hash) ? payload['action'] : nil
            )
          end
        end
      end
    end
  end
end
