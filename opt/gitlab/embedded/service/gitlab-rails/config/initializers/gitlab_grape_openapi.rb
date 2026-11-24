# frozen_string_literal: true

Gitlab::GrapeOpenapi.configure do |config|
  config.info = Gitlab::GrapeOpenapi::Models::Info.new(
    title: 'GitLab REST API',
    description: 'GitLab REST API used to interact with a GitLab installation.',
    version: Gitlab.current_milestone,
    terms_of_service: 'https://handbook.gitlab.com/handbook/legal/api-terms/',
    license: {
      name: 'CC BY-SA 4.0',
      url: 'https://gitlab.com/gitlab-org/gitlab/-/blob/master/LICENSE',
      'x-gitlab-description':
        'The license applies to the OpenAPI specification document itself. ' \
        'For terms governing use of the GitLab API, see the termsOfService field.'
    }
  )

  config.api_prefix = "api"

  config.api_version = "v4"

  config.schema_paths = [Rails.root.join('lib/api/schemas').to_s]

  config.servers = [
    Gitlab::GrapeOpenapi::Models::Server.new(
      url: 'https://{hostname}',
      description: "GitLab REST API",
      variables: {
        hostname: Gitlab::GrapeOpenapi::Models::ServerVariable.new(
          default: 'gitlab.com',
          description: 'Your GitLab instance hostname'
        )
      }
    )
  ]

  config.security_schemes = [
    Gitlab::GrapeOpenapi::Models::SecurityScheme.new(
      name: "bearerAuth",
      type: "http",
      scheme: "bearer"
    ),
    Gitlab::GrapeOpenapi::Models::SecurityScheme.new(
      name: "OAuth2",
      type: "oauth2",
      flows: {
        authorizationCode: {
          authorizationUrl: Gitlab::Utils.append_path('https://gitlab.com', "/oauth/authorize"),
          tokenUrl: Gitlab::Utils.append_path('https://gitlab.com', "/oauth/token"),
          refreshUrl: Gitlab::Utils.append_path('https://gitlab.com', "/oauth/token"),
          scopes: -> {
            Gitlab::Auth::API_SCOPES.reject { |k, _| k == :granular }
                                  .index_with { |s| I18n.t(s, scope: [:doorkeeper, :scope_desc]) }
          }
        }
      }
    ),
    Gitlab::GrapeOpenapi::Models::SecurityScheme.new(
      name: "PRIVATE-TOKEN",
      type: "apiKey",
      in: "header"
    )
  ]

  # key: `route_setting` value
  # value: rendered annotation key
  # e.g. route_setting :lifecycle, "experimental" => YAML: `x-gitlab-lifecycle: experimental`
  config.annotations = {
    lifecycle: 'x-gitlab-lifecycle',
    tier: 'x-gitlab-tier'
  }

  config.tag_overrides = {
    'Ai catalog' => 'AI Catalog',
    'Api' => 'API',
    'bitbucket' => 'Bitbucket',
    'Ci' => 'CI',
    'Code suggestions' => 'Code Suggestions',
    'Dora' => 'DORA',
    'Duo workflows' => 'Duo Workflows',
    'geo' => 'Geo',
    'Github' => 'GitHub',
    'Gitlab duo' => 'GitLab Duo',
    'Gitlab pages' => 'GitLab Pages',
    'Gitlab' => 'GitLab',
    'Gpg' => 'GPG',
    'Glql' => 'GLQL',
    'google cloud' => 'Google Cloud',
    'Jira connect' => 'Jira Connect',
    'Ldap' => 'LDAP',
    'markdown' => 'Markdown',
    'Ml model registry' => 'ML Model Registry',
    'Mlops' => 'MLOps',
    'Mcp' => 'MCP',
    'Npm' => 'NPM',
    'Oauth' => 'OAuth',
    'Pypi' => 'PyPi',
    'Rpm' => 'RPM',
    'Rubygem' => 'RubyGem',
    'Saml' => 'SAML',
    'Scim' => 'SCIM',
    'sidekiq' => 'Sidekiq',
    'Ssh' => 'SSH',
    'Terraform' => 'Terraform',
    'Todos' => 'To-Dos',
    'unleash' => 'Unleash',
    'Vscode' => 'VSCode',
    # Package Registry: render per-format tags as "Packages: <Format>" so they
    # cluster together in the API reference sidebar.
    'Packages cargo' => 'Packages: Cargo',
    'Packages composer' => 'Packages: Composer',
    'Packages conan' => 'Packages: Conan',
    'Packages debian' => 'Packages: Debian',
    'Packages helm' => 'Packages: Helm',
    'Packages npm' => 'Packages: NPM',
    'Packages nuget' => 'Packages: NuGet',
    'Packages pypi' => 'Packages: PyPi',
    'Packages rpm' => 'Packages: RPM',
    'Packages rubygem' => 'Packages: RubyGem'
  }.freeze

  # CONFIGURE COERCER MAPPINGS
  # Maps coerce_with classes to OpenAPI schema properties.
  # When a parameter uses coerce_with and the coercer matches a pattern below,
  # the OpenAPI schema will be generated according to the mapping.
  # For query parameters, style and explode control URL serialization format.
  config.coercer_mappings = {
    # Comma-separated string -> Array of strings (e.g., "bug,feature" -> ["bug", "feature"])
    "CommaSeparatedToArray" => {
      type: "array",
      items_type: "string",
      style: "form",
      explode: false
    },
    # Comma-separated string -> Array of integers (e.g., "1,2,3" -> [1, 2, 3])
    "CommaSeparatedToIntegerArray" => {
      type: "array",
      items_type: "integer",
      style: "form",
      explode: false
    },
    # Hash with string keys -> Hash with integer values
    "HashOfIntegerValues" => {
      type: "object",
      additional_properties: { type: "integer" }
    },
    # Base64-encoded string -> Decoded bytes
    "urlsafe_decode64" => {
      type: "string",
      format: "byte"
    }
  }.freeze

  # CONFIGURE EXCLUDED APIs
  # API endpoints can be excluded from OpenApi spec generation and the resulting
  # documentation by adding their API classes to the excluded_api_classes array.
  # Only add a class when every endpoint in it must be left out. Otherwise, mark
  # the endpoints to leave out with `hidden true`.
  # Grape API classes are not loaded when this config is intitialized.
  # Only use string names. Using class constants will cause loading errors.
  # eg.  config.excluded_api_classes = [ 'API::InternalApiClass', 'API::AdminApiClass' ]
  config.excluded_api_classes = [
    # These classes mount other API classes, so their routes include their children's routes.
    # Documenting them would publish the children even when the children are excluded.
    'API::API',
    'API::RemoteDevelopment::API',
    'GitlabSubscriptions::API::Internal::API',

    # Internal: called by other systems, not by API users. Each line names the caller.
    'API::Ci::Minutes', # CustomersDot, deprecated path
    'API::GitlabSubscriptions::AddOnPurchases', # CustomersDot, deprecated path
    'API::GitlabSubscriptions::Subscriptions', # CustomersDot, deprecated path
    'API::Internal::AppSec::Dast::SiteValidations', # DAST site validation CI job
    'API::Internal::Base', # GitLab Shell, Gitaly
    'API::Internal::Ci::JobRouter', # GitLab agent server (KAS), for runners
    'API::Internal::ErrorTracking', # Error tracking backend
    'API::Internal::Gitaly', # Gitaly
    'API::Internal::Kubernetes', # GitLab agent server (KAS), for agentk
    'API::Internal::Lfs', # GitLab Shell
    'API::Internal::MailRoom', # mail_room
    'API::Internal::Observability', # Workhorse
    'API::Internal::Orbit', # Orbit indexer
    'API::Internal::OrgMover', # Org mover control plane
    'API::Internal::Pages', # GitLab Pages
    'API::Internal::Search::Zoekt', # Zoekt
    'API::Internal::SecretsManager', # OpenBao
    'API::Internal::ServicePing', # Services that report Service Ping for the instance
    'API::Internal::Shellhorse', # GitLab Shell, Workhorse
    'API::Internal::Workhorse', # Workhorse
    'API::RemoteDevelopment::Internal::Agents::Agentw::AgentInfo', # GitLab agent server (KAS), for agentw
    'API::RemoteDevelopment::Internal::Agents::Agentw::AuthorizeUserAccess', # GitLab agent server (KAS), for agentw
    'API::RemoteDevelopment::Internal::Agents::Agentw::ServerConfig', # GitLab agent server (KAS), for agentw
    'API::Scim::GroupScim', # Identity providers (SCIM)
    'API::Scim::InstanceScim', # Identity providers (SCIM)
    'GitlabSubscriptions::API::Internal::AddOnPurchases', # CustomersDot
    'GitlabSubscriptions::API::Internal::ComputeMinutes', # CustomersDot
    'GitlabSubscriptions::API::Internal::Members', # CustomersDot
    'GitlabSubscriptions::API::Internal::NamespaceProjects', # CustomersDot
    'GitlabSubscriptions::API::Internal::Namespaces', # CustomersDot
    'GitlabSubscriptions::API::Internal::Namespaces::Provision', # CustomersDot
    'GitlabSubscriptions::API::Internal::Subscriptions', # CustomersDot
    'GitlabSubscriptions::API::Internal::UpcomingReconciliations', # CustomersDot
    'GitlabSubscriptions::API::Internal::Users', # CustomersDot

    # Test only
    'API::Internal::Coverage'
  ]

  # CONFIGURE CROSS-FIELD VALIDATION EXCEPTIONS
  # API endpoints with groupings of cross-field validators that exceed
  # cross_field_group_limit are not enumerated. These validators include:
  # mutually_exclusive, exactly_one_of, all_or_none_of, at_least_one_of.
  # This configuration generates a custom summary on the endpoint's description.
  # Without an entry, the gem emits a generic counted sentence.
  # eg. config.cross_field_messages = { `POST /api/v4/project` => 'At least one project attribute must be set.' }
  config.cross_field_messages = {
    'PUT /api/v4/application/settings' => 'At least one setting must be updated.',
    'PUT /api/v4/projects/{id}' => 'At least one project attribute must be updated.'
  }.freeze
end
