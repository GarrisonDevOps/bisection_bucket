# frozen_string_literal: true

module Labkit
  module Digest
    module SHA2
      def new(*args, &block)
        bitlen = args.first || 256
        ::OpenSSL::Digest.const_get("SHA#{bitlen}").new
      end
    end
  end

  class FIPS
    OPENSSL_DIGESTS = %i[SHA1 SHA256 SHA384 SHA512].freeze

    class << self
      # Returns whether we should be running in FIPS mode or not
      #
      # @return [Boolean]
      def enabled?
        # Check if it set manually to false
        return false if %w[0 false no].include?(ENV["FIPS_MODE"])

        # Otherwise allow it to be set manually via the env vars
        return true if %w[1 true yes].include?(ENV["FIPS_MODE"])

        # Otherwise, attempt to auto-detect FIPS mode from OpenSSL
        return true if ::OpenSSL.fips_mode

        false
      end

      # Swap Ruby's Digest::SHAx implementations for OpenSSL::Digest::SHAx.
      def enable_fips_mode!
        require "digest"
        require "digest/sha1"
        require "digest/sha2"

        ::Digest::SHA2.singleton_class.prepend(Labkit::Digest::SHA2)
        OPENSSL_DIGESTS.each { |alg| use_openssl_digest(alg, alg) }
      end

      private

      def use_openssl_digest(ruby_algorithm, openssl_algorithm)
        ::Digest.send(:remove_const, ruby_algorithm) # rubocop:disable GitlabSecurity/PublicSend
        ::Digest.const_set(ruby_algorithm, ::OpenSSL::Digest.const_get(openssl_algorithm, false))
      end
    end
  end
end
