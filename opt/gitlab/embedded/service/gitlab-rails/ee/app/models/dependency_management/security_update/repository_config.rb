# frozen_string_literal: true

module DependencyManagement
  module SecurityUpdate
    # Parsed form of `.gitlab/dependency_management.yml`, the registry settings
    # a project commits to its default branch. Administrator settings for
    # auto-remediation stay on the remediation profile.
    #
    # Secret values are never resolved here. `${VARIABLE}` placeholders are
    # emitted verbatim so the real values stay out of Rails logs, the generated
    # pipeline YAML and the workload records. The orchestrator substitutes them
    # inside the update job, where the CI/CD variable is in its environment.
    class RepositoryConfig
      include Gitlab::Utils::StrongMemoize

      CONFIG_PATH = '.gitlab/dependency_management.yml'

      # Namespace for every user-provided variable. The file is Developer-editable
      # while CI/CD variables are Maintainer-provisioned, so the prefix is what
      # stops the file pointing at an unrelated secret such as a deploy token.
      # It is also disjoint from the DEPENDENCY_MANAGEMENT_ variables GitLab sets
      # on the job, which a project variable would otherwise take precedence over.
      # The orchestrator's `ResolveCredentials` checks the same prefix again.
      VARIABLE_PREFIX = 'DS_AUTO_REMEDIATION_'
      # 255 is the check constraint on p_ci_workload_variable_inclusions.variable_name,
      # so anything longer would fail on insert rather than here.
      MAX_VARIABLE_NAME_LENGTH = 255
      VARIABLE_NAME_REGEX = /\A#{VARIABLE_PREFIX}[A-Z0-9_]{1,#{MAX_VARIABLE_NAME_LENGTH - VARIABLE_PREFIX.length}}\z/
      PLACEHOLDER_REGEX = /\A\$\{([A-Za-z_][A-Za-z0-9_]*)\}\z/

      MAX_FILE_SIZE = 16.kilobytes
      MAX_REGISTRIES = 20
      MAX_URL_LENGTH = 2048
      # The schema nests four levels deep. The slack keeps a misplaced list or
      # mapping on the field-level error rather than this one.
      MAX_YAML_DEPTH = 10
      REGISTRY_NAME_REGEX = /\A[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}\z/

      TOP_LEVEL_KEYS = %w[registries].freeze
      REGISTRY_KEYS = %w[kind url username password replaces-base].freeze

      # Translates the file's uniform `kind`/`url`/`username`/`password` shape
      # into a dependabot credential. Dependabot names the URL key and models
      # authentication differently per ecosystem, and the proxy consumes those
      # credentials directly, so the translation has to happen somewhere - here
      # keeps it in the one place that already validates the file.
      #
      # `:basic_auth_token` types take a single `token` that dependabot splits on
      # ":" to build basic auth. `:username_password` types take the pair, and
      # dependabot drops the credential entirely when neither is set.
      #
      # `url_format` is how much of the URL that type's key expects: `:full`
      # keeps the scheme, `:no_scheme` is host and path.
      #
      # Every `url_key` must also be in the orchestrator's `credentialMetadataKeys`,
      # or the updater never sees the registry address.
      KINDS = {
        'npm' => { type: 'npm_registry', url_key: 'registry', auth: :basic_auth_token, url_format: :no_scheme },
        'maven' => { type: 'maven_repository', url_key: 'url', auth: :username_password, url_format: :full },
        'python' => { type: 'python_index', url_key: 'index-url', auth: :basic_auth_token, url_format: :full },
        'rubygems' => { type: 'rubygems_server', url_key: 'url', auth: :basic_auth_token, url_format: :full },
        'go' => { type: 'goproxy_server', url_key: 'url', auth: :username_password, url_format: :full }
      }.freeze

      InvalidConfig = Class.new(StandardError)

      EMPTY = { credentials: [].freeze, variables: [].freeze, error: nil }.freeze

      def initialize(project)
        @project = project
      end

      def valid?
        error.nil?
      end

      def error
        parsed[:error]
      end

      # @return [Array<Hash>] dependabot credentials, placeholders unresolved
      def credentials
        parsed[:credentials]
      end

      # @return [Array<String>] CI/CD variable names the credentials reference,
      #   which are the ones the update job needs exposed
      def variables
        parsed[:variables]
      end

      private

      attr_reader :project

      # The scheduler builds one UpdateService per remediation for the same
      # project, so without the request-level cache each of them would read the
      # same blob from Gitaly again.
      def parsed
        Gitlab::SafeRequestStore.fetch("dependency_management:repository_config:#{project.id}") { parse }
      end
      strong_memoize_attr :parsed

      def parse
        document = config_document
        return EMPTY unless document

        variables = []
        credentials = parse_credentials(document, variables)

        { credentials: credentials, variables: variables.uniq, error: nil }
      rescue InvalidConfig => e
        EMPTY.merge(error: e.message)
      end

      def config_document
        raw = raw_config
        return if raw.blank?

        check_structure!(raw)
        document = YAML.safe_load(raw)
        return if document.nil?

        invalid!('must be a mapping') unless document.is_a?(Hash)

        reject_unknown_keys!(document, TOP_LEVEL_KEYS)

        document
      # Psych builds tagged scalars with Ruby's own conversions, so a bad
      # `!!float` or `!!str` value raises ArgumentError, TypeError or FrozenError.
      rescue Psych::Exception, ArgumentError, TypeError, FrozenError => e
        invalid!("is not valid YAML: #{e.message.truncate(200)}")
      end

      # `safe_load` reads only the first document, so a second one would go
      # unchecked, and a leading empty one would hide the rest of the file.
      #
      # It also recurses once per nesting level, so a few kilobytes of nested
      # brackets raise SystemStackError, which no rescue catches. `Psych.parse_stream`
      # builds the node tree without recursing, so the depth is checked on that.
      def check_structure!(raw)
        documents = Psych.parse_stream(raw).children
        invalid!('must hold a single YAML document') if documents.size > 1

        stack = documents.map { |document| [document, 0] }
        until stack.empty?
          node, depth = stack.pop
          invalid!("nests deeper than #{MAX_YAML_DEPTH} levels") if depth > MAX_YAML_DEPTH
          reject_overriding_keys!(node) if node.is_a?(Psych::Nodes::Mapping)

          node.children&.each { |child| stack << [child, depth + 1] }
        end
      end

      # `safe_load` keeps the last of two equal keys, and merges in any `<<` key,
      # quoted or not. Either way a value the reader of the file does not see
      # can silently replace the `url` they do.
      def reject_overriding_keys!(mapping)
        keys = mapping.children.each_slice(2).filter_map { |key, _| key.value if key.is_a?(Psych::Nodes::Scalar) }
        invalid!('must not use the `<<` merge key') if keys.include?('<<')

        duplicate = keys.tally.find { |_, count| count > 1 }&.first
        invalid!("repeats the key #{describe(duplicate)}") if duplicate
      end

      def raw_config
        ref = project.repository.root_ref
        return if ref.blank?

        # `blob_data_at` loads the whole blob, so a huge file would be read into
        # memory before it could be rejected. The limit caps what Gitaly returns.
        # The full ref stops a tag with the branch's name from being read instead.
        blob = project.repository.blob_at(
          "#{Gitlab::Git::BRANCH_REF_PREFIX}#{ref}", CONFIG_PATH, limit: MAX_FILE_SIZE
        )
        return unless blob

        invalid!("is larger than #{MAX_FILE_SIZE} bytes") if blob.size > MAX_FILE_SIZE

        blob.data
      end

      def parse_credentials(document, variables)
        registries = document['registries']
        return [] if registries.nil?

        invalid!('`registries` must be a mapping') unless registries.is_a?(Hash)
        invalid!("`registries` defines more than #{MAX_REGISTRIES} registries") if registries.size > MAX_REGISTRIES

        registries.map { |name, settings| credential(name, settings, variables) }
      end

      def credential(name, settings, variables)
        # YAML reads an unquoted `on`, `no` or `123` as a boolean or a number.
        invalid!("registry name #{describe(name)} must be a string, so quote it") unless name.is_a?(String)

        unless name.match?(REGISTRY_NAME_REGEX)
          invalid!("registry name #{describe(name)} must be alphanumeric, with dots, dashes or underscores")
        end

        invalid!("registry `#{name}` must be a mapping") unless settings.is_a?(Hash)

        reject_unknown_keys!(settings, REGISTRY_KEYS, "registry `#{name}`")

        kind = KINDS[settings['kind']]
        invalid!("registry `#{name}` must set `kind` to one of: #{KINDS.keys.join(', ')}") unless kind

        {
          'type' => kind[:type],
          kind[:url_key] => registry_url(name, settings, kind)
        }.merge(authentication(name, settings, kind, variables))
          .merge(replaces_base(name, settings, kind))
      end

      def registry_url(name, settings, kind)
        url = settings['url']
        invalid!("registry `#{name}` must set `url` to a string") unless url.is_a?(String) && url.present?

        url = url.strip
        invalid!("registry `#{name}` has a `url` over #{MAX_URL_LENGTH} characters") if url.length > MAX_URL_LENGTH

        # The URL is handed to the updater, where install scripts run, so it must
        # never carry a secret.
        invalid!("registry `#{name}` must not reference a variable in `url`") if url.include?('${')

        uri = parse_uri(name, url)
        unless uri.is_a?(URI::HTTPS) && uri.host.present?
          invalid!("registry `#{name}` must set `url` to an `https://` address")
        end

        # Matched on the string because `URI` reports an empty `https://@host` as
        # having no userinfo.
        if url.match?(%r{\Ahttps://[^/?#]*@}i)
          invalid!("registry `#{name}` must not embed credentials in `url`; use `username` and `password`")
        end

        invalid!("registry `#{name}` must not have a query or fragment in `url`") if uri.query || uri.fragment

        return url unless kind[:url_format] == :no_scheme

        # `uri.scheme` is downcased, so strip against the original spelling.
        url.sub(%r{\Ahttps://}i, '')
      end

      def parse_uri(name, url)
        URI.parse(url)
      rescue URI::InvalidURIError
        invalid!("registry `#{name}` has a malformed `url`")
      end

      def authentication(name, settings, kind, variables)
        username = username_for(name, settings, variables)
        password = password_for(name, settings, variables)

        case kind[:auth]
        when :username_password
          invalid!("registry `#{name}` of kind `#{settings['kind']}` must set `username`") if username.nil?

          { 'username' => username, 'password' => password }
        else
          # Dependabot splits the token on the first ":", so a colon in the
          # username would move part of it into the password. A variable could
          # resolve to one, so the username has to be a literal checked here.
          if username&.match?(PLACEHOLDER_REGEX)
            invalid!("registry `#{name}` of kind `#{settings['kind']}` must set `username` to a literal value")
          end

          if username&.include?(':')
            invalid!("registry `#{name}` of kind `#{settings['kind']}` must not have `:` in `username`")
          end

          { 'token' => username ? "#{username}:#{password}" : password }
        end
      end

      def username_for(name, settings, variables)
        username = settings['username']
        return if username.nil?

        unless username.is_a?(String) && username.present?
          invalid!("registry `#{name}` must set `username` to a string")
        end

        # A `!!binary` value or a control character would pass as a literal and
        # only fail when the job is serialized, or end up inside the token.
        unless username.encoding == Encoding::UTF_8 && username.valid_encoding? && !username.match?(/[[:cntrl:]]/)
          invalid!("registry `#{name}` must set `username` to printable text")
        end

        # A username is not a secret, so a literal is fine. Anything starting with
        # `$` is taken as a placeholder, since that is almost always one missing
        # its braces, and it has to name a usable variable so a typo fails here.
        if username.start_with?('$') || username.include?('${')
          variables << placeholder_variable!(name, 'username', username)
        end

        username
      end

      def password_for(name, settings, variables)
        password = settings['password']

        unless password.is_a?(String) && password.present?
          invalid!("registry `#{name}` must set `password` to a string")
        end

        variables << placeholder_variable!(name, 'password', password)

        password
      end

      def placeholder_variable!(name, key, value)
        variable = value.match(PLACEHOLDER_REGEX)&.captures&.first

        unless variable
          invalid!("registry `#{name}` must set `#{key}` to a `${VARIABLE}` placeholder, not a literal value")
        end

        return variable if variable.match?(VARIABLE_NAME_REGEX)

        invalid!("registry `#{name}` references `#{variable.truncate(50)}` in `#{key}`, which is not an " \
          "upper-case variable name prefixed with `#{VARIABLE_PREFIX}`")
      end

      def replaces_base(name, settings, kind)
        value = settings['replaces-base']
        return {} if value.nil?

        # dependabot only reads it for gem metadata links, and builds their base
        # URL from `host`, which a `rubygems_server` credential does not set.
        if kind[:type] == 'rubygems_server'
          invalid!("registry `#{name}` of kind `rubygems` does not support `replaces-base`")
        end

        return { 'replaces-base' => value } if [true, false].include?(value)

        invalid!("registry `#{name}` must set `replaces-base` to true or false")
      end

      def reject_unknown_keys!(hash, allowed, subject = nil)
        unknown = hash.keys.map(&:to_s) - allowed
        return if unknown.empty?

        keys = unknown.sort.map { |key| describe(key) }.join(', ')
        invalid!([subject, "has unsupported keys: #{keys}"].compact.join(' '))
      end

      def invalid!(reason)
        raise InvalidConfig, "`#{CONFIG_PATH}` #{reason}"
      end

      # Values come from a repository file, so they can be any YAML node. Render
      # them short and quoted rather than interpolating an arbitrary document
      # into the error a user sees.
      def describe(value)
        value.inspect.truncate(50)
      end
    end
  end
end
