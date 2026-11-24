# frozen_string_literal: true

module API
  # Internal API for Openbao to interact with
  # Gitlab application for the Gitlab Secrets Manager feature.
  module Internal
    class SecretsManager < ::API::Base
      feature_category :secrets_management
      MAX_REQUEST_PAYLOAD_SIZE = 1.megabyte
      GITLAB_CONFIG_PATH = '/etc/gitlab/'

      before do
        validate_request!
        authenticate_request_from_openbao!
      end

      helpers do
        include ::Gitlab::Utils::StrongMemoize

        def validate_request!
          # Limit request body size to prevent DoS
          if request.content_type == 'application/json' && request.content_length &&
              request.content_length.to_i < MAX_REQUEST_PAYLOAD_SIZE
            return
          end

          render_api_error!('Invalid content type', :bad_request)
        end

        def authenticate_request_from_openbao!
          return if openbao_authentication_token_secret == authentication_token_from_header

          render_api_error!('Unauthorized', :unauthorized)
        end

        def openbao_authentication_token_secret
          # Prevent symlink-based path traversal attacks.
          file_path = openbao_authentication_token_secret_file_path
          real_path = Pathname.new(file_path).realpath.to_s
          raise "Invalid authentication token file path" unless allowed_root_paths.any? do |allowed_root_path|
            real_path.start_with?(allowed_root_path)
          end

          raise "Authentication token path is not a file" unless File.file?(real_path)

          token_secret = File.read(real_path).chomp
          raise "Empty Openbao authentication token secret" if token_secret.empty?

          token_secret
        rescue Errno::ENOENT, Errno::EACCES => e
          Gitlab::ErrorTracking.track_exception(e)
          raise "Unable to fetch Openbao authentication token secret"
        end
        strong_memoize_attr :openbao_authentication_token_secret

        def openbao_authentication_token_secret_file_path
          Gitlab.config.openbao['authentication_token_secret_file_path']
        end

        def authentication_token_from_header
          headers['Gitlab-Openbao-Auth-Token']
        end

        def allowed_root_paths
          allowed_root_paths = [Rails.root.realpath.to_s + File::SEPARATOR]
          allowed_root_paths << GITLAB_CONFIG_PATH unless Rails.env.development? || Rails.env.test?
          allowed_root_paths
        end

        # OpenBao emits two audit lines per operation: a request-type line and
        # a response-type line. Request-type lines are always discarded by
        # AuditLog#log! and SecretsReadEmitter, so they are not worth a job.
        def request_type_log?(raw_audit_log_json)
          parsed = ::Gitlab::Json.safe_parse(raw_audit_log_json)
          parsed.is_a?(Hash) && parsed['type'] == 'request'
        rescue JSON::ParserError
          # Grape already rejected syntactically invalid JSON, but safe_parse
          # enforces stricter limits (e.g. nesting depth). Such payloads still
          # go through the pipeline so their errors reach error tracking.
          false
        end
      end

      namespace 'internal' do
        namespace 'secrets_manager' do
          resource :audit_logs do
            desc 'Instrument a new audit log' do
              detail 'Creates a new audit log entry for an action performed in Openbao.'
              tags 'secrets_manager'
              success code: 202
            end
            route_setting :authorization, skip_granular_token_authorization: :openbao_token_auth
            post do
              raw_audit_log_json = request.body.read

              # Audit logging is independent of entitlement: OpenBao already served the
              # request by the time this fires, so any resulting action must be auditable
              # regardless of the namespace's Secrets Manager entitlement state.
              #
              # OpenBao blocks its own response on this endpoint, so the audit
              # pipeline (~10 queries incl. writes on the primary) is processed
              # asynchronously to keep the response independent of DB latency.
              unless request_type_log?(raw_audit_log_json)
                # rubocop:disable CodeReuse/Worker -- fire-and-forget ingest endpoint; a service object would only wrap the enqueue
                ::SecretsManagement::AuditLogWorker.perform_async(raw_audit_log_json)
                # rubocop:enable CodeReuse/Worker
              end

              accepted!
            end
          end
        end
      end
    end
  end
end
