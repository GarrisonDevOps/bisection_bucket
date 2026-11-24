# frozen_string_literal: true

require "pg_query"
require "uri"

module Labkit
  module Logging
    # Sanitizer provides log message sanitization, removing
    # confidential information from log messages
    class Sanitizer
      SCP_URL_REGEXP = %r{
        (?:((?:[\-_.!~*()a-zA-Z\d;&=+$,]|%[a-fA-F\d]{2})+)(:(?:(?:[\-_.!~*()a-zA-Z\d;:&=+$,]|%[a-fA-F\d]{2})*))?@)        (?# 1: username, 2: password)
        (?:((?:(?:[a-zA-Z0-9\-._])+|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|\[(?:(?:[a-fA-F\d]{1,4}:)*(?:[a-fA-F\d]{1,4}|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|(?:(?:[a-fA-F\d]{1,4}:)*[a-fA-F\d]{1,4})?::(?:(?:[a-fA-F\d]{1,4}:)*(?:[a-fA-F\d]{1,4}|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))?)\]))) (?# 3: host)
        :
        ((?:[\-_.!~*'()a-zA-Z\d:@&=+$,]|%[a-fA-F\d]{2})*(?:;(?:[\-_.!~*'()a-zA-Z\d:@&=+$,]|%[a-fA-F\d]{2})*)*(?:\/(?:[\-_.!~*'()a-zA-Z\d:@&=+$,]|%[a-fA-F\d]{2})*(?:;(?:[\-_.!~*'()a-zA-Z\d:@&=+$,]|%[a-fA-F\d]{2})*)*)*)? (?# 4: path)
        }x.freeze
      SCP_ANCHORED_URL_REGEXP = /^#{SCP_URL_REGEXP}$/x.freeze
      ALLOWED_SCHEMES = %w[http https ssh git].freeze
      URL_REGEXP = URI::DEFAULT_PARSER.make_regexp(ALLOWED_SCHEMES).freeze

      def self.sanitize_field(content)
        content = content.gsub(URL_REGEXP) { |url| mask_url(url) }
        content.gsub(SCP_URL_REGEXP) { |scp_url| mask_scp_url(scp_url) }
      end

      def self.sanitize_sql(sql)
        PgQuery.normalize(sql)
      rescue PgQuery::ParseError
        ""
      end

      def self.sql_fingerprint(normalized_sql)
        PgQuery.parse(normalized_sql)&.fingerprint
      rescue PgQuery::ParseError
        ""
      end

      # Ensures that URLS are sanitized to hide credentials
      def self.mask_url(url)
        url = url.to_s.strip
        p = URI::DEFAULT_PARSER.parse(url)

        # After upgrading uri to 1.0.0, the DEFAULT_PARSER has been changed from rfc2396 to rfc3986,
        # and there are the following differences in parsing between rfc2396 and rfc3986.
        # e.g:
        #
        #     URI::RFC3986_PARSER.parse('ssh://') => #<URI::Generic ssh://>
        #     URI::RFC2396_PARSER.parse('ssh://') => raise URI::InvalidURIError
        return "" if p.host.empty?

        # Starting from v1.0.4, the `uri` gem clears the `password` instance variable
        # when the `user` setter is called. To preserve the current behavior,
        # we store the `password` in a temporary variable.
        password = p.password

        p.user = "*****" if p.user.present?
        p.password = "*****" if password.present?

        p.to_s
      rescue URI::InvalidURIError
        ""
      end

      # Ensures that URLs of the form user:password@hostname:project.git are
      # sanitized to hide credentials
      def self.mask_scp_url(scp_url)
        scp_url = scp_url.to_s.strip
        m = SCP_ANCHORED_URL_REGEXP.match(scp_url)
        return "" unless m

        password = m[2]
        host = m[3]
        path = m[4]

        return "*****@#{host}:#{path}" unless password.present?

        "*****:*****@#{host}:#{path}"
      end
    end
  end
end
