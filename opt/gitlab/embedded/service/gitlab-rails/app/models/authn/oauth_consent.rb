# frozen_string_literal: true

module Authn
  class OauthConsent < ApplicationRecord
    self.table_name = 'oauth_consents'

    belongs_to :user
    belongs_to :application, class_name: 'Authn::OauthApplication',
      foreign_key: :client_id, primary_key: :uid, inverse_of: false, optional: true

    enum :status, { authorized: 0, rejected: 1, revoked: 2 }

    scope :latest_per_application, -> do
      select('DISTINCT ON (client_id) oauth_consents.*').order(:client_id, created_at: :desc)
    end
    scope :preload_application, -> { preload(application: :owner) }

    # The application as IAM describes it, for a consent whose application was
    # registered on another cell and has no local row. Set per request by the
    # Authorized applications page, never persisted.
    attr_accessor :remote_application

    validates :client_id, presence: true
    validates :consent_challenge, presence: true, uniqueness: true
    validates :granted_scopes, presence: true, unless: :rejected?
    validates :requested_scopes, presence: true
    validate :cannot_update_terminal_consent, on: :update

    # before: read by RevokeService just before it asked IAM to revoke the pair's
    # tokens. A consent created at or after it may belong to an authorization IAM
    # did not touch, so it stays authorized.
    def self.revoke_authorized_for(client_id:, user: nil, before: nil)
      scope = authorized.where(client_id: client_id)
      scope = scope.where(user: user) if user
      scope = scope.where(created_at: ...before) if before
      scope.update_all(status: statuses[:revoked], updated_at: Time.current)
    end

    private

    def cannot_update_terminal_consent
      return unless status_was.in?(%w[revoked rejected])

      errors.add(:status, "#{status_was} consent cannot be modified")
    end
  end
end
