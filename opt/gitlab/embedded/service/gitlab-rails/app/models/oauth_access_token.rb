# frozen_string_literal: true

class OauthAccessToken < Doorkeeper::AccessToken
  include Gitlab::Utils::StrongMemoize
  include Doorkeeper::Concerns::TokenFallback
  include Authz::GranularTokenInterface
  include Authn::IamReplication::Outboxable

  iam_replicable entity_type: 'oauth_access_token'

  belongs_to :application, class_name: 'Authn::OauthApplication'
  belongs_to :organization, class_name: 'Organizations::Organization'

  validates :expires_in, presence: true

  alias_method :user, :resource_owner
  alias_method :user=, :resource_owner=

  scope :latest_per_application, -> { select('distinct on(application_id) *').order(application_id: :desc, created_at: :desc) }
  scope :with_refresh_token, -> { where.not(refresh_token: nil) }
  scope :preload_application, -> { preload(application: :owner) }

  RETENTION_PERIOD = 1.month

  # Doorkeeper revokes with update_all: it runs no callbacks, returns no IDs, and the revoked tokens
  # no longer match its filter. So the outbox rows are recorded first.
  def self.revoke_all_for(application_id, resource_owner, clock = Time)
    transaction do
      # Filtered before batching, not per batch as Outboxable does: one owner and application can have
      # many unrevoked tokens without a refresh token, for example Duo Workflow tokens.
      record_iam_outbox_upserts(
        by_resource_owner(resource_owner).where(application_id: application_id, revoked_at: nil).with_refresh_token
      )

      super
    end
  end

  def self.iam_replicable_scope(relation)
    relation.with_refresh_token
  end

  def scopes=(value)
    if value.is_a?(Array)
      super(Doorkeeper::OAuth::Scopes.from_array(value).to_s)
    else
      super
    end
  end

  def scope_user
    user_id = Authn::ScopedUserExtractor.extract_user_id_from_scopes(scopes)
    return unless user_id

    ::User.find_by_id(user_id)
  end
  strong_memoize_attr :scope_user

  def granular?
    includes_scope?(Gitlab::Auth::GRANULAR_SCOPE)
  end

  def subject_to_granular_enforcement?
    false
  end

  def granular_scopes
    consent_grant ? consent_grant.granular_scopes : Authz::GranularScope.none
  end

  def consent_grant
    Authz::OauthConsentGrant.active_for_user_and_application(resource_owner_id, application_id)
  end
  strong_memoize_attr :consent_grant

  def iam_replication_needed?
    refresh_token.present?
  end

  def iam_outbox_delete_payload
    { owning_cell_id: Gitlab.config.cell.id.to_i, source_id: id }
  end
end
