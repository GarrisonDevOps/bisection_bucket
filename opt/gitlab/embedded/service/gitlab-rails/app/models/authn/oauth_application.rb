# frozen_string_literal: true

module Authn
  class OauthApplication < Doorkeeper::Application
    include EachBatch
    include Doorkeeper::Concerns::TokenFallback
    include FeatureGate
    include IamReplication::Outboxable
    include Cells::Claimable

    iam_replicable entity_type: 'oauth_application'

    cells_claims_attribute :uid, type: CLAIMS_CLAIM_TYPE::CLAIM_TYPE_OAUTH_APPLICATION_UID,
      feature_flag: :cells_claims_oauth_applications

    cells_claims_metadata subject_type: CLAIMS_SUBJECT_TYPE::ORGANIZATION, subject_key: :organization_id

    belongs_to :organization, class_name: 'Organizations::Organization', optional: false

    has_many :oauth_consent_grants, class_name: 'Authz::OauthConsentGrant', foreign_key: :application_id,
      inverse_of: :application
    has_many :oauth_application_granular_scopes, class_name: 'Authz::OauthApplicationGranularScope',
      foreign_key: :application_id, inverse_of: :application, autosave: true
    has_many :granular_scopes, through: :oauth_application_granular_scopes, class_name: 'Authz::GranularScope'

    # Namespace#full_path reads the route; project namespaces have none and fall back to the parent's.
    GRANULAR_SCOPE_PRELOADS = [
      :oauth_application_granular_scopes,
      { granular_scopes: { namespace: [:route, { parent: :route }] } }
    ].freeze

    scope :dynamic, -> { where(dynamic: true) }
    scope :owned_by_users, ->(users) { where(owner_type: 'User', owner_id: users) }
    scope :owned_by_namespaces, ->(namespaces) { where(owner_type: 'Namespace', owner_id: namespaces) }
    scope :with_token_digests, ->(hashed_tokens) do
      return none if hashed_tokens.blank?

      where(secret: hashed_tokens)
    end

    # We explicitly disable device_code_enabled here because it's enabled
    # by default in db/migrate/20260224050659_add_device_code_enabled_to_oauth_applications.rb
    # which is so existing records have the option enabled but all new
    # applications should have device_code_enabled set to false.
    attribute :device_code_enabled, default: -> { false }

    REVOKE_BATCH_SIZE = 100

    # Authorization and refresh need granular while a set is declared, and no other application may carry it.
    before_validation :sync_granular_scope

    # Consents have no FK to the application. Left authorized, a deleted
    # application would still be resolved through IAM on the Authorized applications page.
    before_destroy :revoke_consents

    # Bytes, not characters: a multibyte URL can exceed the 2704-byte btree index entry limit.
    validates :cimd_url, bytesize: { maximum: -> { 2048 } }

    # Application secrets are prefixed gloas-, so the token fallback lookup must
    # not skip them as another token type.
    def self.own_prefix?(plain_secret)
      ::Authn::Tokens::OauthApplicationSecret.prefix?(plain_secret)
    end

    # Hashes raw token
    def self.encode(raw_token_value)
      ::Gitlab::DoorkeeperSecretStoring::Sha512Hash.transform_secret(raw_token_value)
    end

    def self.uid_for(application_id)
      where(id: application_id).pick(:uid)
    end

    def self.exists_for_uid?(uid)
      exists?(uid: uid)
    end

    def self.revoke_non_granular_tokens_and_grants_for(id, resource_owner)
      [OauthAccessToken, OauthAccessGrant].each do |model|
        model.by_resource_owner(resource_owner)
          .where(application_id: id, revoked_at: nil)
          .where.not("string_to_array(COALESCE(scopes, ''), ' ') @> ARRAY[?]", ::Gitlab::Auth::GRANULAR_SCOPE.to_s)
          .each_batch(of: REVOKE_BATCH_SIZE) do |batch|
            model.transaction do
              # Recorded first: the batch filters on revoked_at: nil, so it matches nothing after the update.
              model.record_iam_outbox_upserts(batch) if model.include?(IamReplication::Outboxable)
              batch.update_all(revoked_at: Time.current)
            end
          end
      end
    end

    # Check whether the given plain text secret matches our stored secret
    #
    # @param input [#to_s] Plain secret provided by user
    #        (any object that responds to `#to_s`)
    #
    # @return [Boolean] Whether the given secret matches the stored secret
    #                of this application.
    #
    def secret_matches?(input)
      # return false if either is nil, since secure_compare depends on strings
      # but Application secrets MAY be nil depending on confidentiality.
      return false if input.nil? || secret.nil?

      # When matching the secret by comparer function, all is well.
      return true if secret_strategy.secret_matches?(input, secret)

      self.class.fallback_strategies.each do |fallback_strategy|
        # When fallback lookup is enabled, ensure applications
        # with plain secrets can still be found
        return true if fallback_strategy.secret_matches?(input, secret)
      end
      false
    end

    def granular?
      oauth_application_granular_scopes.any?
    end

    def preload_granular_scopes
      # A just-declared set is already loaded without routes, and the preloader keeps a loaded
      # through target while preloading nested associations on fresh copies the caller never sees
      association(:oauth_application_granular_scopes).reset
      association(:granular_scopes).reset
      ActiveRecord::Associations::Preloader.new(records: [self], associations: GRANULAR_SCOPE_PRELOADS).call

      self
    end

    def iam_routing_enabled?
      Feature.enabled?(:proxy_oauth_requests_to_iam_service, self)
    end

    def iam_outbox_delete_payload
      { uid: uid }
    end

    private

    def revoke_consents
      Authn::OauthConsent.revoke_authorized_for(client_id: uid)
    end

    def sync_granular_scope
      marker = ::Gitlab::Auth::GRANULAR_SCOPE.to_s
      declared = granular?
      return if declared == includes_scope?(marker)

      self.scopes = declared ? scopes.to_a | [marker] : scopes.to_a - [marker]
    end
  end
end
