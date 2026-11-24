# frozen_string_literal: true

class SeedFirstPartyOauthApplications < Gitlab::Database::Migration[2.4]
  milestone '19.6'

  restrict_gitlab_migration gitlab_schema: :gitlab_main

  DEFAULT_ORGANIZATION_ID = 1 # rubocop:disable Gitlab/AvoidConstDefaultOrganizationId -- instance-wide applications live on the default organization

  # The URI schemes registered on the GitLab.com application, per its production change requests:
  # https://gitlab.com/gitlab-com/gl-infra/production/-/work_items/6826 and
  # https://gitlab.com/gitlab-com/gl-infra/production/-/work_items/7942
  VSCODE_SCHEMES = %w[vscode vscode-insiders vscodium].freeze

  # Client IDs are the public GitLab.com ones, so clients work against any instance unchanged.
  APPLICATIONS = [
    {
      uid: '36f2a70cddeb5a0889d4fd8295c241b7e9848e89cf9e599d0eed2d8e5350fbf5',
      name: 'GitLab for VS Code',
      redirect_uri: VSCODE_SCHEMES.map { |scheme| "#{scheme}://gitlab.gitlab-workflow/authentication" }.join("\n"),
      scopes: 'api',
      device_code_enabled: false
    },
    {
      uid: '732efe7d78ba62b01d2a95cd3b02f3ca2a00c7cec32c01e060c1b7664a9aa367',
      name: 'GitLab Duo plugin for JetBrains',
      redirect_uri: 'http://127.0.0.1/api/oauth/gitlab/authorization',
      scopes: 'api',
      device_code_enabled: false
    },
    {
      uid: '41d48f9422ebd655dd9cf2947d6979681dfaddc6d0c56f7628f6ada59559af1e',
      name: 'GitLab CLI',
      redirect_uri: 'http://localhost:7171/auth/redirect',
      # glab requests these scopes; GitLab rejects an authorize request outside the app's scopes (invalid_scope).
      scopes: 'openid profile read_user write_repository api',
      device_code_enabled: true
    }
  ].freeze

  class OauthApplication < MigrationRecord
    self.table_name = 'oauth_applications'
  end

  class Organization < MigrationRecord
    self.table_name = 'organizations'
  end

  def up
    # A new installation runs migrations before the default organization exists, and a cell may not own it.
    return unless Organization.exists?(id: DEFAULT_ORGANIZATION_ID) # rubocop:disable Gitlab/AvoidConstDefaultOrganizationId -- see constant

    OauthApplication.reset_column_information

    APPLICATIONS.each do |attributes|
      next if OauthApplication.exists?(uid: attributes[:uid])

      OauthApplication.create!(
        attributes.merge(
          confidential: false,
          trusted: false,
          ropc_enabled: false,
          organization_id: DEFAULT_ORGANIZATION_ID, # rubocop:disable Gitlab/AvoidConstDefaultOrganizationId -- see constant
          # Public clients have no usable secret, but the column is NOT NULL
          secret: Digest::SHA512.hexdigest(SecureRandom.hex(32))
        )
      )
    end
  end

  def down
    # no-op: admins may have edited or started using these applications
  end
end
