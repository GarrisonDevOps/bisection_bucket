# frozen_string_literal: true

module Security
  module SecretDetection
    module PartnerTokens
      class Registry
        RegistryError = Class.new(StandardError)
        UnsupportedTokenTypeError = Class.new(RegistryError)

        PARTNERS = {
          'AWS' => {
            client_class: ::Security::SecretDetection::PartnerTokens::AwsClient,
            rate_limit_key: :partner_aws_api,
            enabled: true,
            enabled_targets: Scanners::ALL
          }.freeze,
          # GCP
          'GCP API key' => {
            client_class: ::Security::SecretDetection::PartnerTokens::Gcp::ApiKey,
            rate_limit_key: :partner_gcp_api,
            enabled: true,
            enabled_targets: Scanners::ALL
          }.freeze,
          # Postman
          'Postman API token' => {
            client_class: ::Security::SecretDetection::PartnerTokens::PostmanClient,
            rate_limit_key: :partner_postman_api,
            enabled: true,
            enabled_targets: Scanners::ALL
          }.freeze,
          # GitHub
          'Github Personal Access Token' => {
            client_class: ::Security::SecretDetection::PartnerTokens::Github::PersonalAccessToken,
            rate_limit_key: :partner_github_api,
            enabled: true,
            enabled_targets: [Scanners::GSS].freeze
          }.freeze,
          'GithubFineGrainedPersonalAccessToken' => {
            client_class: ::Security::SecretDetection::PartnerTokens::Github::FineGrainedPersonalAccessToken,
            rate_limit_key: :partner_github_api,
            enabled: true,
            enabled_targets: [Scanners::GSS].freeze
          }.freeze,
          'Github OAuth Access Token' => {
            client_class: ::Security::SecretDetection::PartnerTokens::Github::OauthAccessToken,
            rate_limit_key: :partner_github_api,
            enabled: true,
            enabled_targets: [Scanners::GSS].freeze
          }.freeze,
          'GithubAppInstallationToken' => {
            client_class: ::Security::SecretDetection::PartnerTokens::Github::AppInstallationToken,
            rate_limit_key: :partner_github_api,
            enabled: true,
            enabled_targets: [Scanners::GSS].freeze
          }.freeze,
          # OpenAI
          'OpenAiProjectKey' => {
            client_class: ::Security::SecretDetection::PartnerTokens::Openai::ProjectKey,
            rate_limit_key: :partner_openai_api,
            enabled: true,
            enabled_targets: [Scanners::GSS].freeze
          }.freeze,
          'OpenAiServiceAccountKey' => {
            client_class: ::Security::SecretDetection::PartnerTokens::Openai::ServiceAccountKey,
            rate_limit_key: :partner_openai_api,
            enabled: true,
            enabled_targets: [Scanners::GSS].freeze
          }.freeze,
          'OpenAiServiceAdminKey' => {
            client_class: ::Security::SecretDetection::PartnerTokens::Openai::AdminKey,
            rate_limit_key: :partner_openai_api,
            enabled: true,
            enabled_targets: [Scanners::GSS].freeze
          }.freeze,
          'open ai token' => {
            client_class: ::Security::SecretDetection::PartnerTokens::Openai::UserApiKey,
            rate_limit_key: :partner_openai_api,
            enabled: true,
            enabled_targets: [Scanners::GSS].freeze
          }.freeze,
          # Anthropic
          'anthropic_key' => {
            client_class: ::Security::SecretDetection::PartnerTokens::AnthropicClient,
            rate_limit_key: :partner_anthropic_api,
            enabled: true,
            enabled_targets: [Scanners::GSS].freeze
          }.freeze,
          # Heroku
          'Heroku API Key' => {
            client_class: ::Security::SecretDetection::PartnerTokens::HerokuClient,
            rate_limit_key: :partner_heroku_api,
            enabled: true,
            enabled_targets: [Scanners::GSS].freeze
          }.freeze,
          # Stripe
          'StripeLiveSecretKey' => {
            client_class: ::Security::SecretDetection::PartnerTokens::Stripe::LiveSecretKey,
            rate_limit_key: :partner_stripe_api,
            enabled: true,
            enabled_targets: [Scanners::GSS].freeze
          }.freeze,
          'StripeLiveRestrictedKey' => {
            client_class: ::Security::SecretDetection::PartnerTokens::Stripe::LiveRestrictedKey,
            rate_limit_key: :partner_stripe_api,
            enabled: true,
            enabled_targets: [Scanners::GSS].freeze
          }.freeze,
          'StripeLivePublishableKey' => {
            client_class: ::Security::SecretDetection::PartnerTokens::Stripe::LivePublishableKey,
            rate_limit_key: :partner_stripe_api,
            enabled: true,
            enabled_targets: [Scanners::GSS].freeze
          }.freeze,
          'StripeLiveShortSecretKey' => {
            client_class: ::Security::SecretDetection::PartnerTokens::Stripe::LiveShortSecretKey,
            rate_limit_key: :partner_stripe_api,
            enabled: true,
            enabled_targets: [Scanners::GSS].freeze
          }.freeze,
          'StripeTestSecretKey' => {
            client_class: ::Security::SecretDetection::PartnerTokens::Stripe::TestSecretKey,
            rate_limit_key: :partner_stripe_api,
            enabled: true,
            enabled_targets: [Scanners::GSS].freeze
          }.freeze,
          'StripeTestRestrictedKey' => {
            client_class: ::Security::SecretDetection::PartnerTokens::Stripe::TestRestrictedKey,
            rate_limit_key: :partner_stripe_api,
            enabled: true,
            enabled_targets: [Scanners::GSS].freeze
          }.freeze,
          'StripeTestPublishableKey' => {
            client_class: ::Security::SecretDetection::PartnerTokens::Stripe::TestPublishableKey,
            rate_limit_key: :partner_stripe_api,
            enabled: true,
            enabled_targets: [Scanners::GSS].freeze
          }.freeze,
          'StripeTestShortSecretKey' => {
            client_class: ::Security::SecretDetection::PartnerTokens::Stripe::TestShortSecretKey,
            rate_limit_key: :partner_stripe_api,
            enabled: true,
            enabled_targets: [Scanners::GSS].freeze
          }.freeze,
          # Datadog
          'DataDogAPIKey' => {
            client_class: ::Security::SecretDetection::PartnerTokens::DatadogClient,
            rate_limit_key: :partner_datadog_api,
            enabled: true,
            enabled_targets: [Scanners::GSS].freeze
          }.freeze,
          # SendGrid
          'Sendgrid API token' => {
            client_class: ::Security::SecretDetection::PartnerTokens::SendgridClient,
            rate_limit_key: :partner_sendgrid_api,
            enabled: true,
            enabled_targets: [Scanners::GSS].freeze
          }.freeze,
          # npm
          'npm access token' => {
            client_class: ::Security::SecretDetection::PartnerTokens::NpmClient,
            rate_limit_key: :partner_npm_api,
            enabled: true,
            enabled_targets: [Scanners::GSS].freeze
          }.freeze,
          # HashiCorp
          'Hashicorp Terraform user/org API token' => {
            client_class: ::Security::SecretDetection::PartnerTokens::HashicorpTerraformClient,
            rate_limit_key: :partner_hashicorp_api,
            enabled: true,
            enabled_targets: [Scanners::GSS].freeze
          }.freeze,
          # EasyPost
          'EasyPost API token' => {
            client_class: ::Security::SecretDetection::PartnerTokens::EasypostClient,
            rate_limit_key: :partner_easypost_api,
            enabled: true,
            enabled_targets: [Scanners::GSS].freeze
          }.freeze,
          'EasyPost test API token' => {
            client_class: ::Security::SecretDetection::PartnerTokens::EasypostTestClient,
            rate_limit_key: :partner_easypost_api,
            enabled: true,
            enabled_targets: [Scanners::GSS].freeze
          }.freeze,
          # Adafruit IO
          'AdafruitIOKey' => {
            client_class: ::Security::SecretDetection::PartnerTokens::AdafruitClient,
            rate_limit_key: :partner_adafruit_api,
            enabled: true,
            enabled_targets: [Scanners::GSS].freeze
          }.freeze,
          # Asana
          'AsanaPersonalAccessTokenV1' => {
            client_class: ::Security::SecretDetection::PartnerTokens::AsanaV1Client,
            rate_limit_key: :partner_asana_api,
            enabled: true,
            enabled_targets: [Scanners::GSS].freeze
          }.freeze,
          'AsanaPersonalAccessTokenV2' => {
            client_class: ::Security::SecretDetection::PartnerTokens::AsanaV2Client,
            rate_limit_key: :partner_asana_api,
            enabled: true,
            enabled_targets: [Scanners::GSS].freeze
          }.freeze,
          # GoCardless
          'GoCardless API token' => {
            client_class: ::Security::SecretDetection::PartnerTokens::GocardlessClient,
            rate_limit_key: :partner_gocardless_api,
            enabled: true,
            enabled_targets: [Scanners::GSS].freeze
          }.freeze,
          # Fastly
          'Fastly API token' => {
            client_class: ::Security::SecretDetection::PartnerTokens::FastlyClient,
            rate_limit_key: :partner_fastly_api,
            enabled: true,
            enabled_targets: [Scanners::GSS].freeze
          }.freeze,
          # Hugging Face
          'HuggingFaceUserAccessToken' => {
            client_class: ::Security::SecretDetection::PartnerTokens::HuggingfaceClient,
            rate_limit_key: :partner_huggingface_api,
            enabled: true,
            enabled_targets: [Scanners::GSS].freeze
          }.freeze,
          # GC Notify (CDS Canada)
          'CDSCanadaNotifyAPIKey' => {
            client_class: ::Security::SecretDetection::PartnerTokens::GcNotifyClient,
            rate_limit_key: :partner_gcnotify_api,
            enabled: true,
            enabled_targets: [Scanners::GSS].freeze
          }.freeze,
          # Tailscale
          'TailscaleApiAccessToken' => {
            client_class: ::Security::SecretDetection::PartnerTokens::TailscaleClient,
            rate_limit_key: :partner_tailscale_api,
            enabled: true,
            enabled_targets: [Scanners::GSS].freeze
          }.freeze,
          # HubSpot
          'Hubspot API token' => {
            client_class: ::Security::SecretDetection::PartnerTokens::HubspotClient,
            rate_limit_key: :partner_hubspot_api,
            enabled: true,
            enabled_targets: [Scanners::GSS].freeze
          }.freeze,
          # DigitalOcean
          'digitalocean-pat' => {
            client_class: ::Security::SecretDetection::PartnerTokens::DigitaloceanPatClient,
            rate_limit_key: :partner_digitalocean_api,
            enabled: true,
            enabled_targets: [Scanners::GSS].freeze
          }.freeze,
          'digitalocean-access-token' => {
            client_class: ::Security::SecretDetection::PartnerTokens::DigitaloceanOauthClient,
            rate_limit_key: :partner_digitalocean_api,
            enabled: true,
            enabled_targets: [Scanners::GSS].freeze
          }.freeze,
          # Doppler
          'Doppler API token' => {
            client_class: ::Security::SecretDetection::PartnerTokens::DopplerPersonalClient,
            rate_limit_key: :partner_doppler_api,
            enabled: true,
            enabled_targets: [Scanners::GSS].freeze
          }.freeze,
          'Doppler Service token' => {
            client_class: ::Security::SecretDetection::PartnerTokens::DopplerServiceClient,
            rate_limit_key: :partner_doppler_api,
            enabled: true,
            enabled_targets: [Scanners::GSS].freeze
          }.freeze,
          # Flutterwave
          'FlutterwaveProdSecretKey' => {
            client_class: ::Security::SecretDetection::PartnerTokens::FlutterwaveClient,
            rate_limit_key: :partner_flutterwave_api,
            enabled: true,
            enabled_targets: [Scanners::GSS].freeze
          }.freeze,
          'Flutterwave secret key' => {
            client_class: ::Security::SecretDetection::PartnerTokens::FlutterwaveTestClient,
            rate_limit_key: :partner_flutterwave_api,
            enabled: true,
            enabled_targets: [Scanners::GSS].freeze
          }.freeze,
          # Beamer
          'Beamer API token' => {
            client_class: ::Security::SecretDetection::PartnerTokens::BeamerClient,
            rate_limit_key: :partner_beamer_api,
            enabled: true,
            enabled_targets: [Scanners::GSS].freeze
          }.freeze,
          # Pulumi
          'Pulumi API token' => {
            client_class: ::Security::SecretDetection::PartnerTokens::PulumiClient,
            rate_limit_key: :partner_pulumi_api,
            enabled: true,
            enabled_targets: [Scanners::GSS].freeze
          }.freeze,
          # Shippo
          'Shippo API token' => {
            client_class: ::Security::SecretDetection::PartnerTokens::ShippoClient,
            rate_limit_key: :partner_shippo_api,
            enabled: true,
            enabled_targets: [Scanners::GSS].freeze
          }.freeze,
          'Shippo Test API token' => {
            client_class: ::Security::SecretDetection::PartnerTokens::ShippoTestClient,
            rate_limit_key: :partner_shippo_api,
            enabled: true,
            enabled_targets: [Scanners::GSS].freeze
          }.freeze,
          # MessageBird
          'messagebird-api-token' => {
            client_class: ::Security::SecretDetection::PartnerTokens::MessagebirdClient,
            rate_limit_key: :partner_messagebird_api,
            enabled: true,
            enabled_targets: [Scanners::GSS].freeze
          }.freeze,
          # Highnote
          'HighnoteLiveSecretKey' => {
            client_class: ::Security::SecretDetection::PartnerTokens::HighnoteLiveClient,
            rate_limit_key: :partner_highnote_api,
            enabled: true,
            enabled_targets: [Scanners::GSS].freeze
          }.freeze,
          'HighnoteTestSecretKey' => {
            client_class: ::Security::SecretDetection::PartnerTokens::HighnoteTestClient,
            rate_limit_key: :partner_highnote_api,
            enabled: true,
            enabled_targets: [Scanners::GSS].freeze
          }.freeze,
          # Ionic
          'Ionic API token' => {
            client_class: ::Security::SecretDetection::PartnerTokens::IonicClient,
            rate_limit_key: :partner_ionic_api,
            enabled: true,
            enabled_targets: [Scanners::GSS].freeze
          }.freeze,
          # Typeform
          'Typeform API token' => {
            client_class: ::Security::SecretDetection::PartnerTokens::TypeformClient,
            rate_limit_key: :partner_typeform_api,
            enabled: true,
            enabled_targets: [Scanners::GSS].freeze
          }.freeze,
          # Linear
          'Linear API token' => {
            client_class: ::Security::SecretDetection::PartnerTokens::LinearClient,
            rate_limit_key: :partner_linear_api,
            enabled: true,
            enabled_targets: [Scanners::GSS].freeze
          }.freeze,
          # Mailgun
          'Mailgun private API token' => {
            client_class: ::Security::SecretDetection::PartnerTokens::MailgunClient,
            rate_limit_key: :partner_mailgun_api,
            enabled: true,
            enabled_targets: [Scanners::GSS].freeze
          }.freeze,
          # Intercom
          'Intercom API token' => {
            client_class: ::Security::SecretDetection::PartnerTokens::IntercomClient,
            rate_limit_key: :partner_intercom_api,
            enabled: true,
            enabled_targets: [Scanners::GSS].freeze
          }.freeze,
          # Grafana Cloud
          'GrafanaCloudAccessPolicyToken' => {
            client_class: ::Security::SecretDetection::PartnerTokens::GrafanaCloudClient,
            rate_limit_key: :partner_grafana_cloud_api,
            enabled: true,
            enabled_targets: [Scanners::GSS].freeze
          }.freeze,
          # RubyGems
          'Rubygem API token' => {
            client_class: ::Security::SecretDetection::PartnerTokens::RubygemsClient,
            rate_limit_key: :partner_rubygems_api,
            enabled: true,
            enabled_targets: [Scanners::GSS].freeze
          }.freeze,
          # Brevo
          'Sendinblue API token' => {
            client_class: ::Security::SecretDetection::PartnerTokens::BrevoClient,
            rate_limit_key: :partner_brevo_api,
            enabled: true,
            enabled_targets: [Scanners::GSS].freeze
          }.freeze,
          # Dropbox
          'Dropbox short lived API token' => {
            client_class: ::Security::SecretDetection::PartnerTokens::DropboxShortLivedClient,
            rate_limit_key: :partner_dropbox_api,
            enabled: true,
            enabled_targets: [Scanners::GSS].freeze
          }.freeze,
          'DropboxAppAccessToken' => {
            client_class: ::Security::SecretDetection::PartnerTokens::DropboxAppClient,
            rate_limit_key: :partner_dropbox_api,
            enabled: true,
            enabled_targets: [Scanners::GSS].freeze
          }.freeze,
          # Contentful
          'ContentfulPersonalAccessToken' => {
            client_class: ::Security::SecretDetection::PartnerTokens::ContentfulClient,
            rate_limit_key: :partner_contentful_api,
            enabled: true,
            enabled_targets: [Scanners::GSS].freeze
          }.freeze,
          # PostHog
          'PostHogPersonalAPIkey' => {
            client_class: ::Security::SecretDetection::PartnerTokens::PosthogClient,
            rate_limit_key: :partner_posthog_api,
            enabled: true,
            enabled_targets: [Scanners::GSS].freeze
          }.freeze,
          # LangChain
          'LangChainAPIKey' => {
            client_class: ::Security::SecretDetection::PartnerTokens::LangchainClient,
            rate_limit_key: :partner_langchain_api,
            enabled: true,
            enabled_targets: [Scanners::GSS].freeze
          }.freeze,
          # Segment
          'Segment Public API token' => {
            client_class: ::Security::SecretDetection::PartnerTokens::SegmentClient,
            rate_limit_key: :partner_segment_api,
            enabled: true,
            enabled_targets: [Scanners::GSS].freeze
          }.freeze,
          # New Relic
          'New Relic user API Key' => {
            client_class: ::Security::SecretDetection::PartnerTokens::NewRelicClient,
            rate_limit_key: :partner_new_relic_api,
            enabled: true,
            enabled_targets: [Scanners::GSS].freeze
          }.freeze,
          # Lob
          'Lob API Key' => {
            client_class: ::Security::SecretDetection::PartnerTokens::LobClient,
            rate_limit_key: :partner_lob_api,
            enabled: true,
            enabled_targets: [Scanners::GSS].freeze
          }.freeze,
          # Onfido
          'Onfido Live API Token' => {
            client_class: ::Security::SecretDetection::PartnerTokens::OnfidoClient,
            rate_limit_key: :partner_onfido_api,
            enabled: true,
            enabled_targets: [Scanners::GSS].freeze
          }.freeze
        }.freeze

        class << self
          def partner_for(token_type)
            config = PARTNERS[token_type.to_s]
            return unless config && config[:enabled]

            config
          end

          def client_for(token_type)
            config = partner_for(token_type)
            return unless config

            config[:client_class].new
          rescue NameError => e
            Gitlab::ErrorTracking.track_exception(
              e,
              token_type: token_type,
              client_class: config[:client_class]
            )
            nil
          end

          def rate_limit_key_for(token_type)
            config = partner_for(token_type)
            return unless config

            config[:rate_limit_key]
          end

          def enabled_targets_for(token_type)
            config = partner_for(token_type)
            return [] unless config

            config.fetch(:enabled_targets)
          end
        end
      end
    end
  end
end
