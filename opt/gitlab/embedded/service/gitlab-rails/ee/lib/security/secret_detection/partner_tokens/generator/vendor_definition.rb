# frozen_string_literal: true

require 'rack/utils'

module Security
  module SecretDetection
    module PartnerTokens
      module Generator
        # A structured, validated description of how to verify one vendor's
        # token. This is the hand-off contract from the AI-assisted rule
        # development process: an LLM reads the vendor's API docs and emits one
        # of these (as YAML), a human reviews it, and the generator turns
        # it into a verifier class + spec that conform to ADR 006.
        #
        # Keeping the AI output as *data* (not code) is what makes scaling to
        # 60+ vendors safe: the generated code is deterministic and reviewable,
        # and every spec is exercised by the same guardrail suite
        # (unknown-never-inactive, ...).
        class VendorDefinition
          Error = Class.new(StandardError)
          InvalidDefinitionError = Class.new(Error)

          # NOTE: 'query' (token in URL) is intentionally not supported yet: the
          # generator would emit an unauthenticated request, which the vendor
          # rejects with 401 and we'd misreport a live token as inactive. Add it
          # only once the generator wires the token into the URL.
          AUTH_STYLES = %w[bearer header basic_username basic_password].freeze
          # The styles that read auth_param; the others would silently drop it,
          # and the misconfigured client would misreport a live key as inactive.
          AUTH_PARAM_STYLES = %w[header basic_password].freeze
          HTTP_METHODS = %w[get post].freeze
          STATUSES = %w[active inactive unknown].freeze
          # Outcomes the generated client raises for instead of returning a status.
          ERROR_OUTCOMES = %w[rate_limit network_error].freeze

          # The generated client class, e.g. AcmeClient; its file name derives
          # from this via #underscore (AcmeClient -> acme_client.rb).
          CLASS_NAME_PATTERN = /\A[A-Z][A-Za-z0-9]*Client\z/
          # Rule ids may carry spaces, dots, dashes, parens and slashes, e.g.
          # 'Google (GCP) Service-account' or 'Hashicorp Terraform user/org API token'.
          TOKEN_TYPE_PATTERN = %r{\A[A-Za-z0-9 _.\-()/]+\z}
          # Must read as a Ruby symbol, e.g. partner_acme_api.
          RATE_LIMIT_KEY_PATTERN = /\A[a-z][a-z0-9_]*\z/
          # Metrics label, e.g. 'acme'.
          PARTNER_NAME_PATTERN = /\A[A-Za-z0-9 _.-]+\z/
          # An HTTP header name (e.g. DD-API-KEY) or basic-auth username (e.g. api). Capped like
          # extra_headers names so the generated auth prefix example stays within the 120-character limit.
          AUTH_PARAM_PATTERN = /\A[A-Za-z0-9-]{1,40}\z/
          # A scheme in front of the token, e.g. 'AccessKey ' or 'Token token='. It is
          # embedded in a double-quoted string, so '#', quotes and backslashes are excluded.
          AUTH_PREFIX_PATTERN = /\A[A-Za-z0-9][A-Za-z0-9 ._=-]{0,28}[ =]\z/
          # A fixed extra header, e.g. an API version. Quotes, backslashes and '#'
          # are excluded because both parts are embedded in generated source, and
          # the caps keep each generated header line within the 120-character limit.
          HEADER_NAME_PATTERN = /\A[A-Za-z0-9-]{1,40}\z/
          HEADER_VALUE_PATTERN = %r{\A(?! )[A-Za-z0-9 ._:/=+-]{1,48}(?<! )\z}
          # Headers the generator always sets, so extra_headers must not override them.
          RESERVED_HEADERS = %w[authorization accept].freeze
          # A tight vendor pattern starts with literal characters, e.g. \Aghp_...
          FIXED_PREFIX_PATTERN = /\A\\A[A-Za-z0-9_-]{2,}/
          # `test` counts only as the reserved TLD: vendors use it as a host label
          # for sandboxes, e.g. api.us.test.highnote.com.
          PLACEHOLDER_HOST_PATTERN = /\b(example|localhost|placeholder)\b|(\A|\.)test\z/i

          attr_reader :token_type, :class_name, :endpoint, :endpoints, :http_method,
            :auth_style, :auth_param, :token_pattern, :sample_token, :status_map,
            :rate_limit_key, :doc_url, :partner_name, :extra_headers, :auth_prefix

          class << self
            # A vendor with several token types gets one definition (and one client)
            # per type. Building them as a set rejects class-name collisions,
            # which would otherwise regenerate the accept-but-cannot-verify
            # mismatch of https://gitlab.com/gitlab-org/gitlab/-/work_items/588454.
            def build_all(attrs_list)
              definitions = attrs_list.map { |attrs| new(attrs) }

              reject_duplicates!('token_type', definitions.map(&:token_type))
              reject_duplicates!('class_name', definitions.map(&:class_name))

              definitions
            end

            private

            def reject_duplicates!(field, values)
              duplicates = values.tally.select { |_value, count| count > 1 }.keys
              return if duplicates.empty?

              raise InvalidDefinitionError, "duplicate #{field}: #{duplicates.join(', ')} -- " \
                'each token type needs its own definition and its own client class'
            end
          end

          # -- straight-line validation of a data definition
          def initialize(attrs)
            attrs = attrs.transform_keys(&:to_s)

            @token_type     = attrs['token_type']
            @class_name     = attrs['class_name']
            @partner_name   = attrs['partner_name'] || derive_partner_name
            @endpoint       = attrs['endpoint']
            @endpoints      = normalize_endpoints(attrs['endpoints'])
            @http_method    = (attrs['http_method'] || 'get').to_s.downcase
            @auth_style     = attrs['auth_style'].to_s
            @auth_param     = attrs['auth_param'] # header name / basic-auth username
            @auth_prefix    = attrs['auth_prefix']
            @token_pattern  = attrs['token_pattern']
            @sample_token   = attrs['sample_token']
            @status_map     = normalize_status_map(attrs['status_map'])
            @rate_limit_key = attrs['rate_limit_key']
            @doc_url        = attrs['doc_url']
            @extra_headers  = normalize_extra_headers(attrs['extra_headers'])

            validate!
          end

          # Compiles the declarative status_map into the lookup the generator
          # emits case/when branches and adversarial review read from:
          # HTTP code (Integer) => :active | :inactive | :unknown | :rate_limit | :network_error
          def compiled_status_map
            status_map.each_with_object({}) do |(code, outcome), map|
              # 'default' is documentation-only ('unknown' is the only allowed
              # value); compiling it would produce a bogus 0 => :unknown entry.
              next if code == 'default'

              map[code.to_i] = outcome.to_sym
            end
          end

          def regexp
            Regexp.new(token_pattern)
          end

          def multi_host?
            !endpoints.nil?
          end

          private

          # Generated classes always end in Client, so this fits the generator's
          # own output. A vendor with several token types should set partner_name
          # explicitly so all its clients share one metrics label.
          def derive_partner_name
            return unless @class_name

            @class_name.delete_suffix('Client')
          end

          def normalize_status_map(map)
            raise InvalidDefinitionError, 'status_map is required' if map.blank?

            map.transform_keys(&:to_s).transform_values(&:to_s)
          end

          def normalize_endpoints(list)
            return list if list.nil? || list.is_a?(Array)

            raise InvalidDefinitionError, 'endpoints must be a list of URLs'
          end

          def normalize_extra_headers(headers)
            return {} if headers.nil?

            unless headers.is_a?(Hash)
              raise InvalidDefinitionError, 'extra_headers must be a map of header name to value'
            end

            headers.to_h do |name, value|
              # Unquoted YAML scalars arrive as numbers or booleans (1.10 => 1.1),
              # so only strings keep the value exactly as written.
              unless name.is_a?(String) || name.is_a?(Symbol)
                raise InvalidDefinitionError, "extra_headers name must be a string, got #{name.inspect}"
              end

              unless value.is_a?(String)
                raise InvalidDefinitionError,
                  "extra_headers value for #{name} must be a quoted string, got #{value.inspect}"
              end

              [name.to_s, value]
            end
          end

          def validate!
            missing = []
            missing << 'token_type' if token_type.blank?
            missing << 'class_name' if class_name.blank?
            missing << 'endpoint' if endpoint.blank? && !multi_host?
            missing << 'token_pattern' if token_pattern.blank?
            missing << 'sample_token' if sample_token.blank?
            missing << 'rate_limit_key' if rate_limit_key.blank?
            raise InvalidDefinitionError, "missing required fields: #{missing.join(', ')}" if missing.any?

            if HTTP_METHODS.exclude?(http_method)
              raise InvalidDefinitionError, "http_method must be one of #{HTTP_METHODS.join(', ')}"
            end

            if AUTH_STYLES.exclude?(auth_style)
              raise InvalidDefinitionError, "auth_style must be one of #{AUTH_STYLES.join(', ')}"
            end

            validate_class_name!
            validate_endpoints!
            validate_pattern!
            validate_status_map!
            validate_generated_source_fields!
            validate_extra_headers!
            validate_auth_prefix!
            validate_sample_token!
          end

          def validate_class_name!
            return if class_name.match?(CLASS_NAME_PATTERN)

            raise InvalidDefinitionError, "class_name must be CamelCase ending in 'Client', got #{class_name.inspect}"
          end

          # Every field here is interpolated into generated Ruby source that is
          # written to disk and loaded, so each is constrained to a safe
          # character set: a definition (LLM- or human-authored) must never be
          # able to inject code. The generator also emits via escape-safe
          # forms, but this is the authoritative gate (ADR 006, "data, not code").
          def validate_generated_source_fields!
            unless token_type.match?(TOKEN_TYPE_PATTERN)
              raise InvalidDefinitionError, "token_type has unsafe characters: #{token_type.inspect}"
            end

            unless rate_limit_key.to_s.match?(RATE_LIMIT_KEY_PATTERN)
              raise InvalidDefinitionError,
                "rate_limit_key must be a lowercase symbol name, got #{rate_limit_key.inspect}"
            end

            unless partner_name.to_s.match?(PARTNER_NAME_PATTERN)
              raise InvalidDefinitionError, "partner_name has unsafe characters: #{partner_name.inspect}"
            end

            # Keep the pattern print-safe: it drives sample-token generation and
            # '#' would interpolate (#{}, #@, #$) if it were ever embedded in
            # generated source. No real token format needs it.
            if token_pattern.match?(/#|[^[:print:]]/)
              raise InvalidDefinitionError,
                "token_pattern must not contain '#' or control characters: #{token_pattern.inspect}"
            end

            # doc_url lands in a `#` comment line in generated source; a line
            # break would end the comment and let the rest load as Ruby.
            if doc_url.present? && !doc_url.match?(/\A[[:print:]]*\z/)
              raise InvalidDefinitionError,
                "doc_url must not contain control characters or line breaks: #{doc_url.inspect}"
            end

            if auth_style == 'header' && auth_param.blank?
              raise InvalidDefinitionError, "auth_style 'header' requires auth_param (the header name)"
            end

            if auth_param.present? && AUTH_PARAM_STYLES.exclude?(auth_style)
              raise InvalidDefinitionError, "auth_param is ignored by auth_style #{auth_style.inspect}; " \
                "only #{AUTH_PARAM_STYLES.join(' and ')} use it"
            end

            return if auth_param.blank? || auth_param.match?(AUTH_PARAM_PATTERN)

            raise InvalidDefinitionError,
              "auth_param must be up to 40 characters of A-Za-z0-9 and '-', got #{auth_param.inspect}"
          end

          # Names and values are embedded in generated source, like the fields above.
          def validate_extra_headers!
            # Header names are case-insensitive, so 'X-V' and 'x-v' would silently overwrite each other.
            duplicates = extra_headers.keys.map(&:downcase).tally.select { |_name, count| count > 1 }.keys
            if duplicates.any?
              raise InvalidDefinitionError, "extra_headers repeats a header name: #{duplicates.join(', ')}"
            end

            extra_headers.each do |name, value|
              unless name.match?(HEADER_NAME_PATTERN)
                raise InvalidDefinitionError,
                  "extra_headers name must be a valid HTTP header name of up to 40 characters, got #{name.inspect}"
              end

              credential_header = auth_style == 'header' && name.casecmp?(auth_param.to_s)
              if RESERVED_HEADERS.include?(name.downcase) || credential_header
                raise InvalidDefinitionError, "extra_headers cannot set #{name.inspect}; the generator sets it"
              end

              next if value.match?(HEADER_VALUE_PATTERN)

              raise InvalidDefinitionError, "extra_headers value for #{name} must be 1 to 48 of the characters " \
                "A-Za-z0-9 ._:/=+- with no leading or trailing space, got #{value.inspect}"
            end
          end

          def validate_auth_prefix!
            return if auth_prefix.nil?

            if auth_style != 'header'
              raise InvalidDefinitionError, "auth_prefix needs auth_style 'header', got #{auth_style.inspect}"
            end

            return if auth_prefix.is_a?(String) && auth_prefix.match?(AUTH_PREFIX_PATTERN)

            raise InvalidDefinitionError, "auth_prefix must be up to 30 of the characters A-Za-z0-9 ._=-, " \
              "start with a letter or digit and end with a space or '=' (quote it in YAML to keep a " \
              "trailing space), got #{auth_prefix.inspect}"
          end

          def validate_endpoints!
            return validate_endpoint!(endpoint) unless multi_host?

            if endpoint.present?
              raise InvalidDefinitionError, 'endpoint and endpoints are mutually exclusive; ' \
                'list every host under endpoints'
            end

            # A one-host list is endpoint spelled differently; one shape per case keeps definitions uniform.
            if endpoints.size < 2
              raise InvalidDefinitionError, 'endpoints needs at least two hosts; use endpoint for a single host'
            end

            endpoints.each { |url| validate_endpoint!(url) }

            # Two paths on one host is not a region split: a token is live on one of them or on none.
            hosts = endpoints.map { |url| URI.parse(url).host.downcase }
            duplicates = hosts.tally.select { |_host, count| count > 1 }.keys
            return if duplicates.empty?

            raise InvalidDefinitionError,
              "endpoints must be on distinct hosts, got #{duplicates.join(', ')} more than once"
          end

          def validate_endpoint!(url)
            uri = URI.parse(url)
            raise InvalidDefinitionError, "endpoint must be an https URL, got #{url.inspect}" unless
              uri.is_a?(URI::HTTPS)

            # A host-less https endpoint ('https:', 'https://') still parses as
            # URI::HTTPS, so the https check alone would accept it.
            return if uri.host.present? && !uri.host.match?(PLACEHOLDER_HOST_PATTERN)

            raise InvalidDefinitionError,
              "endpoint host is missing or looks like a placeholder/example domain: #{url.inspect}"
          rescue URI::InvalidURIError => e
            raise InvalidDefinitionError, "endpoint is not a valid URL: #{e.message}"
          end

          def validate_pattern!
            pattern = regexp.source
            # A verifier pattern that isn't anchored will happily match a
            # substring of a longer string and send junk to the vendor. ADR 006
            # requires tight, anchored patterns.
            unless pattern.start_with?('\\A') && pattern.end_with?('\\z')
              raise InvalidDefinitionError, 'token_pattern must be anchored with \\A ... \\z'
            end

            # A quantified '.' matches anything, so it defeats both heuristics
            # below ('\Aab.*\z', '\A.{16,}\z'); token formats have explicit
            # character sets, so no real pattern needs it.
            if pattern.match?(/(?<!\\)\.[*+{?]/)
              raise InvalidDefinitionError, "token_pattern must not quantify '.'; " \
                'use an explicit character class'
            end

            # Legitimate vendor tokens can be keyless (Datadog 32-hex), so a
            # pattern is only rejected when it has neither a fixed prefix nor
            # a length constraint.
            return if fixed_prefix?(pattern) || length_constrained?(pattern)

            raise InvalidDefinitionError, 'token_pattern has no fixed prefix and no length ' \
              'constraint; likely too broad and prone to false positives'
          rescue RegexpError => e
            raise InvalidDefinitionError, "token_pattern is not a valid regexp: #{e.message}"
          end

          def fixed_prefix?(pattern)
            pattern.match?(FIXED_PREFIX_PATTERN)
          end

          # A 16+ quantifier over a concrete alphanumeric class -- long enough
          # to avoid false positives without a literal prefix. The class must
          # be narrow: '[\s\S]{16,}' matches any long string and counts for
          # nothing.
          def length_constrained?(pattern)
            pattern.scan(/\[([^\]]+)\]\{(\d+)(?:,\d*)?\}/).any? do |class_body, min|
              min.to_i >= 16 && class_body.match?(/\A[A-Za-z0-9_-]+\z/)
            end
          end

          # The generated spec drives the client with sample_token, so a sample
          # that does not match its own pattern would ship a spec that never
          # exercises the request path.
          def validate_sample_token!
            return if regexp.match?(sample_token)

            raise InvalidDefinitionError,
              "sample_token #{sample_token.inspect} does not match token_pattern #{token_pattern.inspect}"
          end

          def validate_status_map!
            # unknown-never-inactive is enforced structurally: the generator
            # hardcodes the fallthrough for unmapped codes to :unknown, so a
            # 'default' entry can only restate that. Anything else -- inactive
            # above all -- would let the definition claim behavior the generated
            # client does not have.
            if status_map.key?('default') && status_map['default'] != 'unknown'
              raise InvalidDefinitionError, "status_map default can only be 'unknown': unmapped codes fall " \
                "through to unknown and must never be inactive, got #{status_map['default'].inspect}"
            end

            allowed = STATUSES + ERROR_OUTCOMES
            status_map.each do |code, outcome|
              unless allowed.include?(outcome)
                raise InvalidDefinitionError,
                  "status_map outcome #{outcome.inspect} must be one of #{allowed.join(', ')}"
              end

              next if code == 'default'

              unless code.match?(/\A\d{3}\z/) && Rack::Utils::HTTP_STATUS_CODES.key?(code.to_i)
                raise InvalidDefinitionError,
                  "status_map key #{code.inspect} must be an HTTP status code"
              end
            end

            # A map that can never confirm a live or a dead token produces a
            # verifier that only ever answers unknown; such a vendor needs a
            # hand-written client instead of a generated one.
            outcomes = compiled_status_map.values
            if outcomes.exclude?(:active)
              raise InvalidDefinitionError,
                'status_map never yields active; the verifier could never confirm a live token'
            end

            return if outcomes.include?(:inactive)

            raise InvalidDefinitionError,
              'status_map never yields inactive; the verifier could never confirm a dead token'
          end
        end
      end
    end
  end
end
