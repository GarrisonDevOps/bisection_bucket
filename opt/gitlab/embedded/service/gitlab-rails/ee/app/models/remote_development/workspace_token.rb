# frozen_string_literal: true

module RemoteDevelopment
  class WorkspaceToken < ApplicationRecord
    include TokenAuthenticatable

    TOKEN_PREFIX = "glwt-"

    add_authentication_token_field :token,
      encrypted: :required,
      format_with_prefix: :workspace_token_prefix,
      routable_token: {
        payload: {
          o: ->(token_owner_record) { token_owner_record.workspace.project.organization_id },
          u: ->(token_owner_record) { token_owner_record.workspace.user_id }
        }
      }

    belongs_to :workspace, inverse_of: :workspace_token, optional: false

    before_validation :set_project_id, on: :create
    before_validation :ensure_token

    validates :workspace_id, uniqueness: true
    validates :token_encrypted, length: { maximum: 512 }, presence: true
    validates :project_id, presence: true, on: :create

    # @return [String]
    def self.token_prefix
      ::Authn::TokenField::PrefixHelper.prepend_instance_prefix(TOKEN_PREFIX)
    end

    private

    # @return [void]
    def set_project_id
      self.project_id ||= workspace&.project_id

      nil
    end

    # @return [String]
    def workspace_token_prefix
      self.class.token_prefix
    end
  end
end
