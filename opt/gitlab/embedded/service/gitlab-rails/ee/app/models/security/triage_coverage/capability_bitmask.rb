# frozen_string_literal: true

module Security
  module TriageCoverage
    class CapabilityBitmask
      # Append-only: removing or renumbering an entry changes what existing rows' bits silently mean.
      BITS = {
        sbom_ingested: 0,
        sast_false_positive: 1,
        sast_vulnerability_resolution: 2,
        secret_detection_false_positive: 3,
        vulnerability_enrichment: 4
      }.freeze

      ALL_MASK = BITS.values.sum { |bit| 1 << bit }

      def self.trigger_types
        BITS.keys
      end

      def self.mask_for(trigger_type)
        bit = BITS[trigger_type&.to_sym]
        return unless bit

        1 << bit
      end

      # capabilities: { trigger_type => [enabled, is_auto] } -> { triage_capabilities_on:, triage_capabilities_auto: }
      def self.encode(capabilities)
        on = 0
        auto = 0

        capabilities.each do |trigger_type, (enabled, is_auto)|
          mask = mask_for(trigger_type)
          next unless mask && enabled

          on |= mask
          auto |= mask if is_auto
        end

        { triage_capabilities_on: on, triage_capabilities_auto: auto }
      end

      def self.decode(on_mask, auto_mask)
        BITS.map do |trigger_type, bit|
          mask = 1 << bit
          enabled = (on_mask.to_i & mask) != 0
          run_mode = nil

          if enabled && trigger_type != :sbom_ingested
            run_mode = (auto_mask.to_i & mask) != 0 ? :auto : :manual
          end

          { trigger_type: trigger_type, enabled: enabled, run_mode: run_mode }
        end
      end
    end
  end
end
