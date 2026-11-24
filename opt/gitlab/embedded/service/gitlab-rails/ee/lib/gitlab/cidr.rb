# frozen_string_literal: true

require 'ipaddr'

module Gitlab
  class CIDR
    ValidationError = Class.new(StandardError)

    attr_reader :cidrs

    delegate :empty?, to: :cidrs

    def initialize(values)
      @cidrs = parse_cidrs(values)
    end

    def match?(ip)
      cidrs.find { |cidr| cidr.include?(ip) }.present?
    end

    private

    def parse_cidrs(values)
      base = values.to_s.split(',').map do |value|
        ::IPAddr.new(value.strip)
      end

      # Add compatible addresses to match IPv4 allow list entries against IPv4 request IPs
      # that were mapped to IPv6 addresses on the kernel level.
      # https://docs.kernel.org/networking/ip-sysctl.html#proc-sys-net-ipv6-variables
      compats = base.select(&:ipv4?).map(&:ipv4_mapped)

      base + compats
    rescue StandardError => e
      raise ValidationError, e.message
    end
  end
end
