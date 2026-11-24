# frozen_string_literal: true

module Security
  module ScanProfiles
    class Configuration
      class ScanProfileVariables
        SECURE_ANALYZERS_PREFIX = {
          env: 'SECURE_ANALYZERS_PREFIX',
          type: :string,
          label: N_('ScanProfiles|Analyzer image registry'),
          description: N_(
            "ScanProfiles|Pull analyzer images from your own container registry instead of GitLab's public one."
          ),
          placeholder: 'registry.example.com/analyzers'
        }.freeze

        IMAGE_SUFFIX = {
          type: :string,
          label: N_('ScanProfiles|Image variant'),
          description: N_('ScanProfiles|Which build of the analyzer image to pull.'),
          options: [
            { value: '', text: N_('ScanProfiles|Default') },
            { value: '-fips', text: N_('ScanProfiles|FIPS') }
          ]
        }.freeze

        EXCLUDED_PATHS = {
          type: :comma_separated_strings,
          label: N_('ScanProfiles|Paths to exclude'),
          description: N_('ScanProfiles|Paths left out of the scan.'),
          placeholder: 'spec/**'
        }.freeze

        MAPPINGS = {
          secret_detection: {
            secure_analyzers_prefix: SECURE_ANALYZERS_PREFIX,
            image_suffix: { env: 'SECRET_DETECTION_IMAGE_SUFFIX', **IMAGE_SUFFIX },
            historic_scan: {
              env: 'SECRET_DETECTION_HISTORIC_SCAN',
              type: :boolean,
              label: N_('ScanProfiles|Historic scan'),
              description: N_('ScanProfiles|Scan the full Git history instead of only the current state.')
            },
            log_options: {
              env: 'SECRET_DETECTION_LOG_OPTIONS',
              type: :string,
              label: N_('ScanProfiles|Log options'),
              description: N_('ScanProfiles|Options passed to git log to control the commit range scanned.'),
              placeholder: '--since=1.year.ago'
            },
            excluded_paths: { env: 'SECRET_DETECTION_EXCLUDED_PATHS', **EXCLUDED_PATHS },
            ruleset_git_reference: {
              env: 'SECRET_DETECTION_RULESET_GIT_REFERENCE',
              type: :string,
              label: N_('ScanProfiles|Ruleset Git reference'),
              description: N_('ScanProfiles|Git reference of the remote ruleset configuration to use.'),
              placeholder: 'gitlab.com/example-group/remote-ruleset-project'
            }
          },
          sast: {
            secure_analyzers_prefix: SECURE_ANALYZERS_PREFIX,
            image_suffix: { env: 'SAST_IMAGE_SUFFIX', **IMAGE_SUFFIX },
            analyzer_image_tag: {
              env: 'SAST_ANALYZER_IMAGE_TAG',
              type: :string,
              label: N_('ScanProfiles|Analyzer image tag'),
              description: N_('ScanProfiles|Pin the analyzer image to a specific tag.'),
              placeholder: '3.7'
            },
            excluded_analyzers: {
              env: 'SAST_EXCLUDED_ANALYZERS',
              type: :comma_separated_strings,
              label: N_('ScanProfiles|Analyzers to skip'),
              description: N_('ScanProfiles|Analyzers that should not run for this profile.'),
              placeholder: 'semgrep'
            },
            excluded_paths: { env: 'SAST_EXCLUDED_PATHS', **EXCLUDED_PATHS },
            advanced_sast_partial_scan: {
              env: 'ADVANCED_SAST_PARTIAL_SCAN',
              type: :string,
              label: N_('ScanProfiles|Advanced SAST partial scanning'),
              description: N_('ScanProfiles|Controls GitLab Advanced SAST diff-based scanning.'),
              options: [
                { value: 'differential', text: N_('ScanProfiles|Enabled') },
                { value: 'false', text: N_('ScanProfiles|Disabled') }
              ]
            },
            gitlab_adv_sast_incr_scan: {
              env: 'GITLAB_ADV_SAST_INCR_SCAN',
              type: :boolean,
              label: N_('ScanProfiles|Advanced SAST incremental scanning'),
              description: N_('ScanProfiles|Whether GitLab Advanced SAST incremental scanning is enabled.')
            }
          },
          dependency_scanning: {
            secure_analyzers_prefix: SECURE_ANALYZERS_PREFIX,
            additional_ca_cert_bundle: {
              env: 'ADDITIONAL_CA_CERT_BUNDLE',
              type: :string,
              label: N_('ScanProfiles|CA certificate bundle'),
              description: N_('ScanProfiles|CA certificate bundle to trust during the scan.'),
              placeholder: '-----BEGIN CERTIFICATE-----'
            },
            secure_log_level: {
              env: 'SECURE_LOG_LEVEL',
              type: :string,
              label: N_('ScanProfiles|Log level'),
              description: N_('ScanProfiles|Logging level used by the analyzer.'),
              options: [
                { value: 'fatal', text: N_('ScanProfiles|Fatal') },
                { value: 'error', text: N_('ScanProfiles|Error') },
                { value: 'warn', text: N_('ScanProfiles|Warning') },
                { value: 'info', text: N_('ScanProfiles|Info') },
                { value: 'debug', text: N_('ScanProfiles|Debug') }
              ]
            },
            excluded_paths: { env: 'DS_EXCLUDED_PATHS', **EXCLUDED_PATHS },
            include_dev_dependencies: {
              env: 'DS_INCLUDE_DEV_DEPENDENCIES',
              type: :boolean,
              label: N_('ScanProfiles|Include development dependencies'),
              description: N_('ScanProfiles|Include development and test dependencies in the scan.')
            },
            max_depth: {
              env: 'DS_MAX_DEPTH',
              type: :integer,
              label: N_('ScanProfiles|Maximum directory depth'),
              description: N_('ScanProfiles|Directory depth the analyzer scans. -1 scans all directories.'),
              min: -1,
              placeholder: '2'
            },
            pip_dependency_path: {
              env: 'DS_PIP_DEPENDENCY_PATH',
              type: :string,
              label: N_('ScanProfiles|pip dependency path'),
              description: N_('ScanProfiles|Path to install Python packages for analysis.'),
              placeholder: '/pip-cache'
            },
            static_reachability_enabled: {
              env: 'DS_STATIC_REACHABILITY_ENABLED',
              type: :boolean,
              label: N_('ScanProfiles|Static reachability'),
              description: N_('ScanProfiles|Whether static reachability is enabled.')
            },
            enable_manifest_fallback: {
              env: 'DS_ENABLE_MANIFEST_FALLBACK',
              type: :boolean,
              label: N_('ScanProfiles|Manifest fallback'),
              description: N_('ScanProfiles|Whether manifest fallback is enabled.')
            },
            pipcompile_lockfile_file_name_pattern: {
              env: 'DS_PIPCOMPILE_LOCKFILE_FILE_NAME_PATTERN',
              type: :string,
              label: N_('ScanProfiles|pip-compile lockfile name pattern'),
              description: N_('ScanProfiles|File name pattern of pip-compile lockfiles to analyze.'),
              placeholder: 'requirements*.txt'
            },
            pip_manifest_file_name_pattern: {
              env: 'DS_PIP_MANIFEST_FILE_NAME_PATTERN',
              type: :string,
              label: N_('ScanProfiles|pip manifest name pattern'),
              description: N_('ScanProfiles|File name pattern of pip manifests to resolve and scan.'),
              placeholder: 'requirements*.txt'
            },
            enable_vulnerability_scan: {
              env: 'DS_ENABLE_VULNERABILITY_SCAN',
              type: :boolean,
              label: N_('ScanProfiles|Vulnerability scan'),
              description: N_('ScanProfiles|Whether generated SBOMs are analyzed for vulnerabilities.')
            },
            api_timeout: {
              env: 'DS_API_TIMEOUT',
              type: :integer,
              label: N_('ScanProfiles|API timeout'),
              description: N_('ScanProfiles|Vulnerability scanning API timeout in seconds, from 5 to 300.'),
              min: 5,
              max: 300,
              placeholder: '10'
            },
            api_scan_download_delay: {
              env: 'DS_API_SCAN_DOWNLOAD_DELAY',
              type: :integer,
              label: N_('ScanProfiles|API download delay'),
              description: N_(
                'ScanProfiles|Seconds to wait before downloading vulnerability scan results, from 1 to 120.'
              ),
              min: 1,
              max: 120,
              placeholder: '3'
            },
            maven_dependency_plugin_version: {
              env: 'DS_MAVEN_DEPENDENCY_PLUGIN_VERSION',
              type: :string,
              label: N_('ScanProfiles|maven-dependency-plugin version'),
              description: N_('ScanProfiles|Version of maven-dependency-plugin used during resolution.'),
              placeholder: '3.8.1'
            },
            maven_args: {
              env: 'MAVEN_ARGS',
              type: :string,
              label: N_('ScanProfiles|Maven arguments'),
              description: N_('ScanProfiles|Additional arguments passed to Maven during resolution.'),
              placeholder: '--settings ci_settings.xml'
            },
            gradle_cli_opts: {
              env: 'GRADLE_CLI_OPTS',
              type: :string,
              label: N_('ScanProfiles|Gradle options'),
              description: N_('ScanProfiles|Additional command-line options passed to Gradle during resolution.'),
              placeholder: '-Dhttps.proxyHost=proxy.example.com'
            },
            disabled_resolution_jobs: {
              env: 'DS_DISABLED_RESOLUTION_JOBS',
              type: :comma_separated_strings,
              label: N_('ScanProfiles|Resolution jobs to skip'),
              description: N_('ScanProfiles|Dependency resolution jobs that should not run.'),
              options: [
                { value: 'maven', text: N_('ScanProfiles|Maven') },
                { value: 'gradle', text: N_('ScanProfiles|Gradle') },
                { value: 'python', text: N_('ScanProfiles|Python') }
              ],
              placeholder_text: N_('ScanProfiles|Select jobs to skip')
            },
            maven_resolution_image: {
              env: 'DS_MAVEN_RESOLUTION_IMAGE',
              type: :string,
              label: N_('ScanProfiles|Maven resolution image'),
              description: N_('ScanProfiles|Image used by the Maven dependency resolution job.'),
              placeholder: 'registry.example.com/maven:3.9'
            },
            gradle_resolution_image: {
              env: 'DS_GRADLE_RESOLUTION_IMAGE',
              type: :string,
              label: N_('ScanProfiles|Gradle resolution image'),
              description: N_('ScanProfiles|Image used by the Gradle dependency resolution job.'),
              placeholder: 'registry.example.com/gradle:8'
            },
            python_resolution_image: {
              env: 'DS_PYTHON_RESOLUTION_IMAGE',
              type: :string,
              label: N_('ScanProfiles|Python resolution image'),
              description: N_('ScanProfiles|Image used by the Python dependency resolution job.'),
              placeholder: 'registry.example.com/python:3.12'
            },
            pip_index_url: {
              env: 'PIP_INDEX_URL',
              type: :string,
              label: N_('ScanProfiles|pip index URL'),
              description: N_('ScanProfiles|Base URL of the Python Package Index.'),
              placeholder: 'https://pypi.example.com/simple'
            },
            pip_extra_index_url: {
              env: 'PIP_EXTRA_INDEX_URL',
              type: :space_separated_strings,
              label: N_('ScanProfiles|pip extra index URLs'),
              description: N_('ScanProfiles|Additional Python package indexes to use.'),
              placeholder: 'https://pypi.example.com/simple'
            },
            search_ignore_hidden_dirs: {
              env: 'SEARCH_IGNORE_HIDDEN_DIRS',
              type: :boolean,
              label: N_('ScanProfiles|Ignore hidden directories'),
              description: N_('ScanProfiles|Skip hidden directories when searching for supported files.')
            }
          }
        }.freeze

        private_constant :SECURE_ANALYZERS_PREFIX, :IMAGE_SUFFIX, :EXCLUDED_PATHS
      end
    end
  end
end
