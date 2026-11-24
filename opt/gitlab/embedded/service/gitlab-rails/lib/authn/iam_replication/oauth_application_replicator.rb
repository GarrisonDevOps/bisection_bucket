# frozen_string_literal: true

# Sends Authn::OauthApplication rows to IAM, so every replication layer sends identical requests.

module Authn
  module IamReplication
    class OauthApplicationReplicator
      def self.reconciliation_enabled?
        Feature.enabled?(:iam_replication_reconciliation_oauth_applications, :instance, type: :ops)
      end

      def self.reconciliation_scope
        ::Authn::OauthApplication.preload(:organization, :owner) # rubocop:disable CodeReuse/ActiveRecord -- scope owned by the Layer 4 reconciliation
      end

      def initialize(client: nil, timeout: nil, report_transient_errors: true)
        @client = client || ::Authn::IamService::GrpcClient.new(
          timeout: timeout, report_transient_errors: report_transient_errors
        )
      end

      # Returns a ::Authn::IamReplication::Results value: DELIVERED, or SKIPPED if the record is gone.
      # Raises on transport failure; callers decide what to record.
      def deliver(outbox_event)
        case outbox_event.event_type
        when 'upsert'
          application = ::Authn::OauthApplication.find_by_id(outbox_event.entity_id)

          # Absent means the record was removed after this row was written
          return ::Authn::IamReplication::Results::SKIPPED unless application

          upsert(application)
        when 'delete'
          delete_upstream(outbox_event.payload.symbolize_keys.fetch(:uid))
          ::Authn::IamReplication::Results::DELIVERED
        else
          raise ArgumentError, "unhandled event_type: #{outbox_event.event_type}"
        end
      end

      def upsert(application)
        client.upsert_oauth_application(**upsert_attributes(application))
        ::Authn::IamReplication::Results::DELIVERED
      end

      # Layer 4 only. Returns [application, outcome, IAM message, IAM reason] for each application, in input order.
      def bulk_upsert(applications)
        clients = applications.map { |application| upsert_attributes(application) }
        # IAM refuses an empty list, and a batch is empty when its rows were deleted during the pass.
        return [] if clients.empty?

        results = client.bulk_upsert_oauth_applications(clients: clients).results
        unless results.size == clients.size
          raise ::Authn::IamService::GrpcClient::RequestError,
            "IAM returned #{results.size} results for #{clients.size} clients"
        end

        applications.zip(results).map do |application, result|
          # IAM refuses a record for the checks that make UpsertClient answer INVALID_ARGUMENT.
          outcome =
            if result.reason == :REASON_WRITTEN
              ::Authn::IamReplication::Results::DELIVERED
            else
              ::Authn::IamReplication::Results::INVALID_REQUEST
            end

          [application, outcome, result.message.presence, result.reason.to_s]
        end
      end

      private

      attr_reader :client

      # NOT_FOUND means the client is already gone, which is the desired end
      # state, so it counts as delivered. Layer 2 usually deletes it first.
      def delete_upstream(uid)
        client.delete_oauth_application(client_id: uid)
      rescue ::Authn::IamService::GrpcClient::RequestError => error
        raise unless error.reason == :not_found
      end

      def upsert_attributes(application)
        {
          client_id: application.uid,
          hashed_client_secret: ::Authn::IamReplication::HashedSecret.of(application.secret),
          redirect_uris: application.redirect_uri.split,
          grant_types: grant_types(application),
          response_types: %w[code],
          scopes: application.scopes.to_a,
          public: !application.confidential?,
          client_name: application.name,
          owner: owner_label(application),
          trusted: application.trusted?,
          created_at: timestamp(application.created_at),
          updated_at: timestamp(application.updated_at),
          dynamic: application.dynamic?,
          organization_id: application.organization.uuid,
          owning_cell_id: Gitlab.config.cell.id.to_i,
          source_id: application.id
        }
      end

      # Mirrors auth_helper#auth_app_owner_text
      def owner_label(application)
        return if application.dynamic?
        return 'An administrator' unless application.owner

        application.owner.name
      end

      # Grant types are per-application and intentionally decoupled from Doorkeeper.config,
      # since Doorkeeper's flows are instance-wide while IAM needs per-application types.
      # Omitting `device_code` as not implemented yet in IAM.
      def grant_types(application)
        types = %w[authorization_code refresh_token]
        types << 'client_credentials' if application.confidential?
        types
      end

      def timestamp(time)
        ::Google::Protobuf::Timestamp.new(seconds: time.to_i)
      end
    end
  end
end
