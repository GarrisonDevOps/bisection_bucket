# frozen_string_literal: true

module Authn
  module IamReplication
    class OauthAccessTokenReplicator
      # Tokens revoked before the sweep first ran were never live in IAM, so the sweep skips them.
      REVOCATION_CUTOFF = Date.new(2026, 10, 21)

      def self.reconciliation_enabled?
        Feature.enabled?(:iam_replication_reconciliation_oauth_access_tokens, :instance, type: :ops)
      end

      def self.reconciliation_scope
        # rubocop:disable CodeReuse/ActiveRecord -- scope owned by the Layer 4 reconciliation
        ::OauthAccessToken
          .with_refresh_token
          .where.not(application_id: nil)
          .where(revoked_at: [nil, REVOCATION_CUTOFF..])
          .preload(:application)
        # rubocop:enable CodeReuse/ActiveRecord
      end

      def initialize(client: nil, timeout: nil, report_transient_errors: true)
        @client = client || ::Authn::IamService::GrpcClient.new(
          timeout: timeout, report_transient_errors: report_transient_errors
        )
      end

      # Returns a ::Authn::IamReplication::Results value: DELIVERED, or SKIPPED if there is nothing to send.
      # Raises on transport failure; callers decide what to record.
      def deliver(outbox_event)
        case outbox_event.event_type
        when 'upsert'
          token = ::OauthAccessToken.find_by_id(outbox_event.entity_id)

          # Absent means the record was removed after this row was written
          return ::Authn::IamReplication::Results::SKIPPED unless token

          upsert(token)
        when 'delete'
          # No IAM delete endpoint yet, see https://gitlab.com/gitlab-org/gitlab/-/work_items/632077
          ::Authn::IamReplication::Results::SKIPPED
        else
          raise ArgumentError, "unhandled event_type: #{outbox_event.event_type}"
        end
      end

      def upsert(token)
        # The application can be deleted without its tokens.
        return ::Authn::IamReplication::Results::SKIPPED unless token.application

        client.upsert_oauth_refresh_token(**upsert_attributes(token))
        ::Authn::IamReplication::Results::DELIVERED
      end

      # Layer 4 only. Returns [token, outcome, IAM message, IAM reason] for each token.
      def bulk_upsert(tokens)
        with_application, without_application = tokens.partition(&:application)
        skipped = without_application.map { |token| [token, ::Authn::IamReplication::Results::SKIPPED, nil, nil] }
        return skipped if with_application.empty?

        records = with_application.map { |token| upsert_attributes(token) }
        results = client.bulk_upsert_oauth_refresh_tokens(tokens: records).results
        unless results.size == records.size
          raise ::Authn::IamService::GrpcClient::RequestError,
            "IAM returned #{results.size} results for #{records.size} tokens"
        end

        skipped + with_application.zip(results).map do |token, result|
          [token, outcome_for(result.reason), result.message.presence, result.reason.to_s]
        end
      end

      private

      attr_reader :client

      # No expires_at: Doorkeeper refresh tokens never expire.
      def upsert_attributes(token)
        {
          signature: ::Authn::IamReplication::HashedSecret.of(token.refresh_token),
          client_id: token.application.uid,
          subject: token.resource_owner_id.to_s,
          scopes: token.scopes.to_a,
          revoked_at: (timestamp(token.revoked_at) if token.revoked_at),
          created_at: timestamp(token.created_at),
          owning_cell_id: Gitlab.config.cell.id.to_i,
          source_id: token.id
        }
      end

      def outcome_for(reason)
        case reason
        when :REASON_WRITTEN then ::Authn::IamReplication::Results::DELIVERED
        # Retryable once the client replicates, as FAILED_PRECONDITION from the single Upsert.
        when :REASON_CLIENT_NOT_FOUND then ::Authn::IamReplication::Results::FAILED_PRECONDITION
        else ::Authn::IamReplication::Results::INVALID_REQUEST
        end
      end

      def timestamp(time)
        ::Google::Protobuf::Timestamp.new(seconds: time.to_i)
      end
    end
  end
end
