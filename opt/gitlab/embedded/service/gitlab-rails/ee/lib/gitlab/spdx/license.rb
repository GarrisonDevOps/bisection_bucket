# frozen_string_literal: true

module Gitlab
  module SPDX
    class License
      EXPOSED_ATTRIBUTES = %i[
        id
        name
        url
        deprecated
        spdx_identifier
      ].freeze

      def initialize(id:, name:, deprecated: false)
        @id = id
        @name = name
        @deprecated = deprecated
      end

      def self.unknown
        new(id: 'unknown', name: 'Unknown')
      end

      attr_reader :id, :name, :deprecated
      alias_method :spdx_identifier, :id

      def url
        "https://spdx.org/licenses/#{id}.html"
      end

      def key?(key)
        !self[key].nil?
      end

      def [](key)
        return unless EXPOSED_ATTRIBUTES.include?(key)

        # rubocop:disable GitlabSecurity/PublicSend -- Mitigated with allowlist
        public_send(key)
        # rubocop:enable GitlabSecurity/PublicSend
      end

      def canonical_id
        spdx_identifier || name&.downcase
      end
    end
  end
end
