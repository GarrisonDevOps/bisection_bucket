# frozen_string_literal: true

module Utilization
  module BillableUsage
    module Exports
      # CustomersDot strips the checksum keys and recomputes the digest, so both sides
      # hash the same canonical form: JSON round-tripped, Hash keys sorted recursively,
      # array order kept.
      class Checksum
        ALGORITHM = 'sha256'
        CHECKSUM_KEYS = %w[checksum checksum_algorithm].freeze

        def self.seal(document)
          unsealed = canonical(document).except(*CHECKSUM_KEYS)

          unsealed.merge('checksum_algorithm' => ALGORITHM, 'checksum' => hexdigest(unsealed))
        end

        def self.digest(document)
          hexdigest(canonical(document).except(*CHECKSUM_KEYS))
        end

        def self.canonical(document)
          # rubocop:disable Gitlab/JsonSafeParse -- our own document, which can exceed SafeParser's element limits
          Gitlab::Json.parse(Gitlab::Json.dump(document))
          # rubocop:enable Gitlab/JsonSafeParse
        end
        private_class_method :canonical

        def self.hexdigest(unsealed)
          Digest::SHA256.hexdigest(Gitlab::Json.dump(deep_sort(unsealed)))
        end
        private_class_method :hexdigest

        def self.deep_sort(value)
          case value
          when Hash
            value.sort.to_h.transform_values { |val| deep_sort(val) }
          when Array
            value.map { |val| deep_sort(val) }
          else
            value
          end
        end
        private_class_method :deep_sort
      end
    end
  end
end
