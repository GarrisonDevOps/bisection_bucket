# frozen_string_literal: true

module PackageMetadata
  class SyncConfiguration
    include Gitlab::Utils::StrongMemoize

    VERSION_FORMAT_V2 = 'v2'
    VERSION_FORMAT_V3 = 'v3'

    PURL_TYPE_TO_REGISTRY_ID = {
      composer: "packagist",
      conan: "conan",
      gem: "rubygem",
      golang: "go",
      maven: "maven",
      npm: "npm",
      nuget: "nuget",
      pypi: "pypi",
      apk: "apk",
      rpm: "rpm",
      deb: "deb",
      'cbl-mariner': "cbl-mariner",
      wolfi: "wolfi",
      cargo: "cargo",
      swift: "swift",
      conda: "conda",
      pub: "pub",
      not_provided: "none",
      unknown: "none"
    }.with_indifferent_access.freeze

    def self.configs_for(data_type)
      case data_type
      when 'cve_enrichment'
        cve_enrichment_configs
      when 'advisories'
        advisory_configs
      when 'licenses'
        license_configs
      when 'malware_advisories'
        malware_advisory_configs
      else
        raise ArgumentError, "unsupported data type: #{data_type}"
      end
    end

    def self.cve_enrichment_configs
      storage_type, base_uri = Location.for_cve_enrichment
      [new('cve_enrichment', storage_type, base_uri, VERSION_FORMAT_V2, nil)]
    end

    def self.advisory_configs
      storage_type, base_uri = Location.for_advisories
      version_format = Location.advisories_version_format(storage_type, base_uri)

      permitted_purl_types.map do |purl_type, _|
        new('advisories', storage_type, base_uri, version_format, purl_type)
      end
    end

    def self.license_configs
      storage_type, base_uri = Location.for_licenses
      version_format = Location.licenses_version_format(storage_type, base_uri)

      permitted_purl_types.map do |purl_type, _|
        new('licenses', storage_type, base_uri, version_format, purl_type)
      end
    end

    def self.malware_advisory_configs
      storage_type, base_uri = Location.for_malware_advisories

      permitted_purl_types.map do |purl_type, _|
        new('malware_advisories', storage_type, base_uri, VERSION_FORMAT_V3, purl_type)
      end
    end

    def self.registry_id(purl_type)
      PURL_TYPE_TO_REGISTRY_ID[purl_type].freeze
    end

    def self.permitted_purl_types
      ::Gitlab::CurrentSettings.current_application_settings.package_metadata_purl_types_names
    end

    attr_accessor :data_type, :storage_type, :base_uri, :version_format, :purl_type

    def initialize(data_type, storage_type, base_uri, version_format, purl_type)
      @data_type = data_type
      @storage_type = storage_type
      @base_uri = base_uri
      @version_format = version_format
      @purl_type = purl_type
    end

    def v2?
      version_format == VERSION_FORMAT_V2
    end

    def v3?
      version_format == VERSION_FORMAT_V3
    end

    def advisories?
      data_type == 'advisories'
    end

    def cve_enrichment?
      data_type == 'cve_enrichment'
    end

    def to_s
      "#{data_type}:#{storage_type}/#{base_uri}/#{version_format}/#{purl_type}"
    end
    strong_memoize_attr :to_s

    class Location
      LICENSES_PATH = Rails.root.join('vendor/package_metadata/licenses').freeze
      # old licenses path did not differentiate between data_types
      OLD_LICENSES_PATH = Rails.root.join('vendor/package_metadata_db').freeze
      LICENSES_BUCKET = 'prod-export-license-bucket-1a6c642fc4de57d4'
      ADVISORIES_PATH = Rails.root.join('vendor/package_metadata/advisories').freeze
      ADVISORIES_BUCKET = 'prod-export-advisory-bucket-1a6c642fc4de57d4'
      CVE_ENRICHMENT_PATH = Rails.root.join('vendor/package_metadata/cve_enrichment').freeze
      CVE_ENRICHMENT_BUCKET = 'prod-export-cve-enrichment-bucket-1a6c642fc4de57d4'
      MALWARE_ADVISORIES_PATH = Rails.root.join('vendor/package_metadata/malware_advisories').freeze
      # PDS (PMDB Distribution Service) endpoints for online sync. One service,
      # one endpoint per dataset.
      # See https://gitlab.com/gitlab-org/gitlab/-/work_items/602430
      PDS_MALWARE_ENDPOINT = 'https://pmdb-dist-svc.runway.gitlab.net/v1/malware/advisories'
      PDS_MALWARE_STAGING_ENDPOINT = 'https://pmdb-dist-svc.staging.runway.gitlab.net/v1/malware/advisories'
      PDS_LICENSES_ENDPOINT = 'https://pmdb-dist-svc.runway.gitlab.net/v1/licenses'
      PDS_LICENSES_STAGING_ENDPOINT = 'https://pmdb-dist-svc.staging.runway.gitlab.net/v1/licenses'
      PDS_ADVISORIES_ENDPOINT = 'https://pmdb-dist-svc.runway.gitlab.net/v1/advisories'
      PDS_ADVISORIES_STAGING_ENDPOINT = 'https://pmdb-dist-svc.staging.runway.gitlab.net/v1/advisories'

      # The storage type drives the checkpoint row, the worker's service and the
      # connector; licenses_version_format adds which layout an offline root holds.
      # A vendored directory wins over the flag.
      def self.for_licenses
        if File.exist?(LICENSES_PATH)
          [:offline, LICENSES_PATH]
        elsif File.exist?(OLD_LICENSES_PATH)
          [:offline, OLD_LICENSES_PATH]
        elsif sync_v3_licenses?
          [:pds, licenses_pds_endpoint]
        else
          [:gcp, LICENSES_BUCKET]
        end
      end

      # A vendored directory wins over the flag, as it does for licenses: an
      # air-gapped instance has no route to PDS.
      def self.for_advisories
        if File.exist?(ADVISORIES_PATH)
          [:offline, ADVISORIES_PATH]
        elsif sync_v3_advisories?
          [:pds, advisories_pds_endpoint]
        else
          [:gcp, ADVISORIES_BUCKET]
        end
      end

      def self.for_cve_enrichment
        if File.exist?(CVE_ENRICHMENT_PATH)
          [:offline, CVE_ENRICHMENT_PATH]
        else
          [:gcp, CVE_ENRICHMENT_BUCKET]
        end
      end

      # Malware advisories sync from PDS online, or from an admin-unpacked
      # vendor directory (air-gapped). Offline takes precedence when present.
      def self.for_malware_advisories
        if File.exist?(MALWARE_ADVISORIES_PATH)
          [:offline, MALWARE_ADVISORIES_PATH]
        else
          [:pds, malware_pds_endpoint]
        end
      end

      def self.malware_pds_endpoint
        pds_endpoint(production: PDS_MALWARE_ENDPOINT, staging: PDS_MALWARE_STAGING_ENDPOINT)
      end

      def self.licenses_pds_endpoint
        pds_endpoint(production: PDS_LICENSES_ENDPOINT, staging: PDS_LICENSES_STAGING_ENDPOINT)
      end

      def self.advisories_pds_endpoint
        pds_endpoint(production: PDS_ADVISORIES_ENDPOINT, staging: PDS_ADVISORIES_STAGING_ENDPOINT)
      end

      # Licenses are v3 once the flag is on, with one exception: an offline root
      # holding no v3 data falls back to v2, so an instance that has not mirrored
      # v3 yet keeps getting license updates.
      def self.licenses_version_format(storage_type, base_uri)
        return VERSION_FORMAT_V2 unless sync_v3_licenses?
        return VERSION_FORMAT_V2 if storage_type == :offline && !v3_vendored?(base_uri)

        VERSION_FORMAT_V3
      end

      # v3 is served from PDS, and from an offline root that holds a v3 layout.
      # Everything else stays v2: the public bucket only ever holds v2, and an
      # offline root that has not mirrored v3 keeps getting advisory updates
      # through the layout it does have.
      def self.advisories_version_format(storage_type, base_uri)
        return VERSION_FORMAT_V2 unless sync_v3_advisories?
        return VERSION_FORMAT_V3 if storage_type == :pds
        return VERSION_FORMAT_V3 if storage_type == :offline && v3_vendored?(base_uri)

        VERSION_FORMAT_V2
      end

      # Presence alone, no structural check: completeness is the writer's job here,
      # the same as v2. The download script publishes v3 with a single rename.
      def self.v3_vendored?(root)
        File.exist?(File.join(root, VERSION_FORMAT_V3))
      end

      def self.sync_v3_advisories?
        Feature.enabled?(:sync_v3_advisories, :instance)
      end

      # Read twice per run, by the worker and by the service, and both reads must agree.
      def self.sync_v3_licenses?
        Feature.enabled?(:sync_v3_license_expressions, :instance)
      end

      # Only a production deployment reaches the production PDS. Every other
      # environment, including one we do not recognise, falls back to staging.
      def self.pds_endpoint(production:, staging:)
        production_deployment? ? production : staging
      end

      # staging.gitlab.com runs with RAILS_ENV=production, so the Rails env alone
      # does not identify production.
      def self.production_deployment?
        Rails.env.production? && !Gitlab.staging?
      end
    end
  end
end

# Added for JiHu
# Used in https://jihulab.com/gitlab-cn/gitlab/-/blob/main-jh/jh/app/models/jh/package_metadata/sync_configuration.rb
PackageMetadata::SyncConfiguration::Location.prepend_mod
