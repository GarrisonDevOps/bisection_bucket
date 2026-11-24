# frozen_string_literal: true

module Gitlab
  module DuoWorkflow
    # Builds the shell commands that install and configure the glab CLI inside a
    # Duo Agent Platform workload.
    #
    # The config goes under GLAB_CONFIG_DIR, set by {Sandbox#environment_variables}.
    class GlabSetup
      # Version only enforced if glab is not already installed in the image.
      VERSION = "1.124.0"

      # Vetted digests from the release's checksums.txt. Pinning the digest as
      # well as the tag means a retagged release fails the install instead of
      # silently changing the binary. Keyed by version so bumping VERSION
      # without refreshing the digests raises rather than pairing a new release
      # with stale digests.
      CHECKSUMS = {
        "1.124.0" => {
          "darwin_amd64" => "6adb7155566bedd6272d8f286e6c75b080d0050a349de4bed79661226d10d954",
          "darwin_arm64" => "04aad4d989d98cb030318e09359f02e0ba2637ede682ec0dee1f5974dedd44c1",
          "linux_amd64" => "63df684842b0697e418649dd64374d37ac1da0fbcdcb422d6a5557222f8bb40f",
          "linux_arm64" => "0716395a0efeb991fc844b33fe55310645afcbd9b9746e50c725e9d1cd1b8d16"
        }
      }.freeze

      GLAB_BIN_DIR = "/tmp/bin"
      GLAB_EXTRACT_DIR = "/tmp/glab"
      GLAB_ARCHIVE = "#{GLAB_EXTRACT_DIR}/glab.tar.gz".freeze

      class << self
        def install_command
          <<~BASH.squish
            if command -v glab > /dev/null 2>&1; then
              echo "glab already present, skipping installation";
            else
              (
                set -o pipefail &&
                echo "Installing glab@#{VERSION}..." &&
                GLAB_OS=$(uname -s | tr '[:upper:]' '[:lower:]') &&
                GLAB_ARCH=$(uname -m) &&
                case "$GLAB_ARCH" in
                  x86_64) GLAB_ARCH=amd64 ;;
                  aarch64|arm64) GLAB_ARCH=arm64 ;;
                  *) echo "Unsupported architecture: $GLAB_ARCH" >&2; exit 1 ;;
                esac &&
                mkdir -p #{GLAB_BIN_DIR} #{GLAB_EXTRACT_DIR} &&
                curl --silent --show-error --fail --location --output #{GLAB_ARCHIVE} "#{download_url}" &&
                #{checksum_verification_command} &&
                tar --extract --gzip --file #{GLAB_ARCHIVE} --directory #{GLAB_EXTRACT_DIR} &&
                mv #{GLAB_EXTRACT_DIR}/bin/glab #{GLAB_BIN_DIR}/
              ) || echo "Warning: glab installation failed; continuing without glab" >&2;
            fi
          BASH
        end

        private

        def checksums
          CHECKSUMS.fetch(VERSION) do
            raise "No vetted glab checksums for #{VERSION}. Refresh CHECKSUMS from " \
              "https://gitlab.com/gitlab-org/cli/-/releases/v#{VERSION}/downloads/checksums.txt"
          end
        end

        def checksum_verification_command
          platforms = checksums.map { |platform, digest| "#{platform}) GLAB_SHA256=#{digest} ;;" }

          # " *" rather than sha256sum's default two spaces, which `squish` would
          # collapse into one and sha256sum would reject as a malformed line.
          <<~BASH.squish
            case "${GLAB_OS}_${GLAB_ARCH}" in
              #{platforms.join(' ')}
              *) echo "No vetted glab checksum for ${GLAB_OS}_${GLAB_ARCH}" >&2; exit 1 ;;
            esac &&
            echo "$GLAB_SHA256 *#{GLAB_ARCHIVE}" | sha256sum --check --quiet
          BASH
        end

        def download_url
          "https://gitlab.com/gitlab-org/cli/-/releases/v#{VERSION}/downloads/" \
            "glab_#{VERSION}_${GLAB_OS}_${GLAB_ARCH}.tar.gz"
        end
      end

      def initialize(current_user:)
        @current_user = current_user
      end

      def commands
        setup_commands + config_commands + skills_install_commands
      end

      private

      def setup_commands
        glab_version_warning =
          'glab not working. Execution will continue but it is recommended that glab ' \
            'is properly installed to allow Agents access to GitLab.'

        [
          self.class.install_command,
          %(export PATH="#{GLAB_BIN_DIR}:$PATH"),
          %(which glab || echo "glab not in PATH"),
          %(glab version || echo "#{glab_version_warning}")
        ]
      end

      def config_commands
        [
          'mkdir -p "$GLAB_CONFIG_DIR"',
          config_file_command,
          'chmod 600 "$GLAB_CONFIG_DIR/config.yml"'
        ]
      end

      def skills_install_commands
        # Skills must be present before `duo run` so the Duo CLI can discover
        # them at startup and include them in the workspace_agent_skills context
        # sent to the AI Gateway. Global install (~/.agents/skills/) keeps
        # skill files outside the repo so they are not accidentally committed.
        # The Orbit skill comes from {OrbitSetup}.
        [
          %(glab skills install --global || echo "Warning: glab skills install failed; continuing without glab skills")
        ]
      end

      def config_file_command
        # Build the config as a Ruby hash and serialize with `to_yaml` so
        # indentation is handled correctly
        host_config = {
          "is_oauth2" => "true",
          "client_id" => "bypass",
          "oauth2_refresh_token" => "",
          "oauth2_expiry_date" => "01 Jan 2050 00:00 UTC",
          "api_host" => host,
          "api_protocol" => protocol,
          "user" => @current_user.username
        }
        host_config["subfolder"] = subfolder if subfolder.present?

        config = {
          "hosts" => { host => host_config },
          "check_update" => "false",
          "git_protocol" => protocol
        }

        # umask 077 creates the file as 0600, so it is never readable by others
        # before the chmod. The subshell keeps the umask from leaking into later
        # commands.
        <<~GLAB_CONFIG_COMMAND.chomp
          (umask 077 && cat > "$GLAB_CONFIG_DIR/config.yml" <<'GLAB_CONFIG'
          #{config.to_yaml.chomp}
          GLAB_CONFIG
          )
        GLAB_CONFIG_COMMAND
      end

      def host
        gitlab_uri.port == gitlab_uri.default_port ? gitlab_uri.host : "#{gitlab_uri.host}:#{gitlab_uri.port}"
      end

      # glab's first-class field for a relative URL root (e.g. "/gitlab").
      def subfolder
        Gitlab.config.gitlab.relative_url_root.to_s.delete_prefix('/').delete_suffix('/')
      end

      def protocol
        gitlab_uri.scheme
      end

      def gitlab_uri
        @gitlab_uri ||= URI.parse(Gitlab.config.gitlab.url)
      end
    end
  end
end
