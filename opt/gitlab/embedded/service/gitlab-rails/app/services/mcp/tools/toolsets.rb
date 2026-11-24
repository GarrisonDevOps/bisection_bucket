# frozen_string_literal: true

module Mcp
  module Tools
    module Toolsets
      ALWAYS_ON  = %i[meta].freeze
      DEFAULT    = %i[core merge_requests work_items repository ci duo_agent_platform].freeze
      OPT_IN     = %i[wikis code_security orbit].freeze
      ALL        = (ALWAYS_ON + DEFAULT + OPT_IN).freeze
      UNASSIGNED = :unassigned

      def self.parse(header_value)
        names = normalize(header_value)
        return if names.empty?

        return ALL.map(&:to_s) if names.include?('all')

        names
      end

      def self.selection(header_value)
        names = normalize(header_value)

        if names.empty?
          { source: 'default', names: [] }
        elsif names.include?('all')
          { source: 'all', names: [] }
        else
          { source: 'explicit', names: names.uniq.sort }
        end
      end

      def self.normalize(header_value)
        return [] if header_value.blank?

        names = header_value.split(',').map { |name| name.strip.downcase }.reject(&:blank?)

        valid = ALL.map(&:to_s)
        invalid = names - valid - ['all']
        if invalid.any?
          raise ArgumentError,
            "Unknown toolsets: #{invalid.join(', ')}. Valid toolsets: #{valid.join(', ')}"
        end

        names
      end
      private_class_method :normalize

      def self.defaults
        (DEFAULT + ALWAYS_ON).map(&:to_s)
      end
    end
  end
end
