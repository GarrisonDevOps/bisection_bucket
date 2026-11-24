# frozen_string_literal: true

module Gitlab
  module RateLimit
    # The rate-limit bucket for a client address. IPv6 clients are usually given a
    # whole prefix, so they are bucketed by network. IPv4 addresses, including
    # IPv4-mapped IPv6 ones, stay exact.
    module IpBucket
      DEFAULT_IPV6_PREFIX_LENGTH = 64

      class << self
        # The value the per-IP rate limits count a client by.
        #
        # @param ip [String, nil] the client address
        # @return [String, nil] the {.mask} of the ip at the instance's
        #   ipv6_rate_limit_prefix_length, or the ip unchanged while
        #   rate_limiter_bucket_ipv6_by_prefix is disabled
        def for(ip)
          # IPv4 never changes, so most traffic skips the flag read.
          return ip if ip.present? && ip.exclude?(':')
          return ip unless ::Feature.enabled?(:rate_limiter_bucket_ipv6_by_prefix, ::Feature.current_request)

          mask(ip, ::Gitlab::CurrentSettings.ipv6_rate_limit_prefix_length)
        end

        # @param ip [String, nil] the client address, as Rack or ActionDispatch reports it
        # @param ipv6_prefix_length [Integer] the network prefix an IPv6 address is masked to
        # @return [String, nil] the masked IPv6 network or the IPv4 address. Returns nil
        #   for an empty ip. Returns the ip unchanged when it is not a single address
        #   (malformed, or with a CIDR suffix or zone ID), or when the prefix length
        #   is not in 0..128, so it keeps its own bucket.
        def mask(ip, ipv6_prefix_length)
          return if ip.nil? || ip.empty?
          # Without a colon it is IPv4 or malformed, and both stay exact, so skip the parse.
          return ip if ip.include?('/') || ip.include?('%') || ip.exclude?(':')

          bucket(ip, ipv6_prefix_length)
        end

        private

        def bucket(ip, ipv6_prefix_length)
          address = IPAddr.new(ip).native
          address = address.mask(ipv6_prefix_length) if address.ipv6?
          address.to_s
        rescue ArgumentError # IPAddr::Error is one, also for a bad prefix length, and invalid UTF-8 raises a plain one
          ip
        end
      end
    end
  end
end
