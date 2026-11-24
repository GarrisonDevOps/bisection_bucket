# frozen_string_literal: true

module Gitlab
  module IpRestriction
    class Enforcer
      def initialize(group)
        @group = group
      end

      def logger
        @logger ||= Gitlab::AuthLogger.build
      end

      # Every group under one top-level group shares its restrictions and licensed features, so the answer is
      # cached for the request per top-level group and IP address.
      def allows_current_ip?
        return true unless group

        current_ip_address = Gitlab::IpAddressState.current

        return true unless current_ip_address

        cache_key = [:ip_restriction_allows_current_ip, group.traversal_ids.first, current_ip_address]

        Gitlab::SafeRequestStore.fetch(cache_key) do
          check_current_ip(current_ip_address)
        end
      end

      private

      attr_reader :group

      def check_current_ip(address)
        return true unless group.licensed_feature_available?(:group_ip_restriction)

        allows_address?(address)
      end

      def allows_address?(address)
        root_ancestor_ip_restrictions = group.root_ancestor_ip_restrictions

        return true unless root_ancestor_ip_restrictions.present?

        allowed = root_ancestor_ip_restrictions.any? { |ip_restriction| ip_restriction.allows_address?(address) }

        # Check against configured internal ranges
        allowed ||= globally_configured_ip_ranges.match?(address)

        logger.info(
          message: 'Attempting to access IP restricted group',
          group_full_path: group.full_path,
          ip_address: address,
          allowed: allowed,
          global_allowlist_in_use: globally_configured_ip_ranges.present?
        )

        allowed
      end

      def globally_configured_ip_ranges
        ::Gitlab::CIDR.new(Gitlab::CurrentSettings.globally_allowed_ips)
      end
    end
  end
end
