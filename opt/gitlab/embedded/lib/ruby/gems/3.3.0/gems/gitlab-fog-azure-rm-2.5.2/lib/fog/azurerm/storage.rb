# frozen_string_literal: true

require 'json'
require 'time'

module Fog
  module AzureRM
    # This class registers models, requests and collections
    class Storage < Fog::Service
      # Recognizes when creating data client
      recognizes :azure_storage_account_name
      recognizes :azure_storage_access_key
      recognizes :azure_storage_token_signer
      recognizes :azure_storage_endpoint
      recognizes :azure_storage_domain
      recognizes :environment
      recognizes :api_version

      recognizes :debug

      request_path 'fog/azurerm/requests/storage'
      # Azure Storage Container requests
      request :create_container
      request :release_container_lease
      request :acquire_container_lease
      request :delete_container
      request :list_containers
      request :put_container_metadata
      request :get_container_properties
      request :get_container_acl
      request :put_container_acl
      request :get_container_url
      request :check_container_exists
      # Azure Storage Blob requests
      request :list_blobs
      request :put_blob_metadata
      request :put_blob_properties
      request :get_blob_properties
      request :copy_blob
      request :copy_object
      request :copy_blob_from_uri
      request :compare_container_blobs
      request :acquire_blob_lease
      request :release_blob_lease
      request :get_blob
      request :get_blob_url
      request :get_object
      request :get_object_url
      request :get_blob_http_url
      request :get_blob_https_url
      request :create_block_blob
      request :put_blob_block
      request :put_blob_http_url
      request :put_blob_https_url
      request :put_object_url
      request :delete_blob
      request :delete_blob_https_url
      request :delete_object_url
      request :delete_object
      request :commit_blob_blocks
      request :create_page_blob
      request :put_blob_pages
      request :wait_blob_copy_operation_to_finish
      request :save_page_blob

      model_path 'fog/azurerm/models/storage'
      model :directory
      collection :directories
      model :file
      collection :files

      # This class provides the mock implementation for unit tests.
      class Mock
        def initialize(_options = {})
          begin
            require 'azure/storage/common'
            require 'azure/storage/blob'
          rescue LoadError => e
            retry if require('rubygems')
            raise e.message
          end
        end
      end

      # This class provides the actual implementation for service calls.
      class Real
        include Fog::AzureRM::Utilities::General

        attr_accessor :options

        # Immutable snapshot of a built SharedAccessSignature and the delegation
        # key expiry it is valid until. It is published by a single reference
        # assignment so signature_client can read it on a lock-free fast path.
        # A nil expiry means the signature never expires (shared-key auth, which
        # signs with the access key rather than a user delegation key).
        class SignatureState
          attr_reader :client, :expiry

          def initialize(client, expiry)
            @client = client
            @expiry = expiry
            freeze
          end

          def covers?(requested_expiry)
            expiry.nil? || expiry >= requested_expiry
          end
        end

        def initialize(options)
          begin
            require 'azure/storage/common'
            require 'azure/storage/blob'
            require 'securerandom'
            @debug = ENV['DEBUG'] || options[:debug]
            require 'azure/core/http/debug_filter' if @debug
            require 'fog/azurerm/identity_encoding_filter'
          rescue LoadError => e
            retry if require('rubygems')
            raise e.message
          end

          @credential_mutex = Mutex.new
          @signature_mutex = Mutex.new

          options[:environment] = options[:environment] || ENV['AZURE_ENVIRONMENT'] || ENVIRONMENT_AZURE_CLOUD
          @environment = options[:environment]
          @options = options

          @azure_storage_account_name = options[:azure_storage_account_name]
          @azure_storage_access_key = options[:azure_storage_access_key]
          @api_version = options[:api_version]

          load_credentials

          @azure_storage_token_signer = token_signer
          @azure_storage_endpoint = options[:azure_storage_endpoint]
          @azure_storage_domain = options[:azure_storage_domain]

          @blob_client = build_blob_client(@azure_storage_token_signer)
        end

        private

        def load_credentials
          return options[:azure_storage_token_signer] if options[:azure_storage_token_signer]
          return if @azure_storage_access_key && !@azure_storage_access_key.empty?

          @credential_client = Fog::AzureRM::DefaultCredentials.new(options)
          @credentials = @credential_client.fetch_credentials_if_needed
        end

        def token_signer
          return options[:azure_storage_token_signer] if options[:azure_storage_token_signer]
          return unless @credentials

          access_token_signer(@credentials.token)
        end

        def access_token_signer(access_token)
          cred = Azure::Storage::Common::Core::TokenCredential.new(access_token)
          Azure::Storage::Common::Core::Auth::TokenSigner.new(cred)
        end

        # Returns a SharedAccessSignature for signing a URL that expires at
        # requested_expiry.
        #
        # A user delegation key is valid for up to a week
        # (MAX_USER_DELEGATION_KEY_SECONDS), so the built signature is cached in
        # a frozen @signature_state snapshot and reused on a lock-free fast path.
        # This keeps signing off the lock in the common case, so an in-flight
        # credential or delegation-key refresh on another thread never stalls it.
        #
        # Only the slow path (no cached signature, or the cached delegation key
        # no longer covers the requested expiry) takes @signature_mutex, where
        # the delegation-key fetch and the snapshot rebuild happen atomically.
        # Holding the lock there also collapses a burst of concurrent refetches
        # into a single fetch.
        def signature_client(requested_expiry)
          # Keep the blob client's credentials fresh without blocking signing;
          # see maybe_refresh_credentials.
          maybe_refresh_credentials

          state = @signature_state
          return state.client if state&.covers?(requested_expiry)

          @signature_mutex.synchronize do
            # Re-check: another thread may have rebuilt the snapshot while we
            # were waiting for the lock.
            state = @signature_state
            return state.client if state&.covers?(requested_expiry)

            delegation_key = fetch_user_delegation_key(requested_expiry)
            client = Azure::Storage::Common::Core::Auth::SharedAccessSignature.new(
              @azure_storage_account_name,
              @azure_storage_access_key.to_s,
              delegation_key
            )
            @signature_state = SignatureState.new(client, @user_delegation_key_expiry)
            client
          end
        end

        # Refreshes the credential-derived state (@credentials, the token signer
        # and the blob client) when the access token is near expiry. The SAS URL
        # requests reach this through signature_client, and the data-plane
        # requests reach it through the blob_client reader, so both keep their
        # token fresh across rotation.
        #
        # The refresh is best-effort and non-blocking: a token fetch can be slow
        # (or hang), so only one thread performs it at a time via a try-lock, and
        # every other thread proceeds with the current, still-valid credentials
        # rather than waiting. This keeps a slow token endpoint from stalling all
        # callers that share the instance.
        #
        # The new signer and client are built into locals first and @credentials
        # is published last. If building raises, @credentials is unchanged so
        # refresh_needed? stays true and the next call retries, rather than
        # leaving the swap half-applied with a stale signer or client.
        def maybe_refresh_credentials
          return unless @credential_client

          current = @credentials
          return unless current.nil? || current.refresh_needed?
          return unless @credential_mutex.try_lock

          begin
            return unless @credentials.nil? || @credentials.refresh_needed?

            new_credentials = @credential_client.fetch_credentials_if_needed
            return if new_credentials.nil? || new_credentials == @credentials

            signer = access_token_signer(new_credentials.token)
            client = build_blob_client(signer)

            @azure_storage_token_signer = signer
            @blob_client = client
            @credentials = new_credentials
          ensure
            @credential_mutex.unlock
          end
        end

        # Reader for the data-plane blob client. It refreshes an expiring access
        # token first, so operations that read the client directly (blob
        # properties, downloads, uploads, deletes) stay authenticated across
        # token rotation, not only the SAS URL path. See
        # https://gitlab.com/gitlab-org/ruby/gems/gitlab-fog-azure-rm/-/issues/11
        def blob_client
          maybe_refresh_credentials
          @blob_client
        end

        # Returns the cached user delegation key, fetching a new one when the
        # cache is empty or no longer covers requested_expiry. Must be called
        # while holding @signature_mutex. Returns nil for shared-key auth, where
        # the SAS is signed with the access key instead.
        def fetch_user_delegation_key(requested_expiry)
          return nil unless @azure_storage_token_signer

          if @user_delegation_key_expiry.nil? || @user_delegation_key_expiry < requested_expiry
            start = Time.now
            expiry = start + Azure::Storage::Blob::BlobConstants::MAX_USER_DELEGATION_KEY_SECONDS

            @user_delegation_key = @blob_client.get_user_delegation_key(start, expiry)
            # Cache against the expiry Azure granted (signed_expiry), not the one
            # we requested: Azure uses its own clock and may return an earlier
            # time, and keying on the request would over-claim validity and emit
            # SAS URLs that Azure rejects.
            @user_delegation_key_expiry = Time.parse(@user_delegation_key.signed_expiry)
          end

          @user_delegation_key
        end

        # Builds and returns a fully configured blob client. The caller publishes
        # it with a single reference assignment (see initialize and
        # maybe_refresh_credentials), so a concurrent reader of @blob_client never
        # observes a client that is missing its filters mid-build.
        def build_blob_client(signer)
          azure_client = create_azure_client(signer)
          azure_client.storage_blob_host = storage_blob_host
          client = Azure::Storage::Blob::BlobService.new(client: azure_client, api_version: @api_version)
          client.with_filter(Fog::AzureRM::IdentityEncodingFilter.new)
          client.with_filter(Azure::Storage::Common::Core::Filter::ExponentialRetryPolicyFilter.new)
          client.with_filter(Azure::Core::Http::DebugFilter.new) if @debug
          client
        end

        def storage_blob_host
          return @azure_storage_endpoint if @azure_storage_endpoint

          if @azure_storage_domain.nil? || @azure_storage_domain.empty?
            get_blob_endpoint(@azure_storage_account_name, true, @environment)
          else
            get_blob_endpoint_with_domain(@azure_storage_account_name, true, @azure_storage_domain)
          end
        end

        def create_azure_client(signer)
          Azure::Storage::Common::Client.create({
            storage_account_name: @azure_storage_account_name,
            storage_access_key: @azure_storage_access_key,
            signer: signer
          }.compact)
        end
      end
    end
  end
end
