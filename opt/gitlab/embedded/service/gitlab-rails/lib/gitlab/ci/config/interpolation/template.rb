# frozen_string_literal: true

module Gitlab
  module Ci
    class Config
      module Interpolation
        class Template
          attr_reader :blocks, :ctx

          MAX_BLOCKS = 10_000
          TOO_LARGE_ERROR = 'interpolated config is too large'
          BLOCK_REGEXP = Gitlab::UntrustedRegexp.new('(?<block>\$\[\[\s*(?<data>\S{1}.*?\S{1})\s*\]\])')
          BLOCK_PREFIX = '$[['

          def initialize(config, ctx, size_tracker: nil)
            @config = Interpolation::Config.fabricate(config)
            @ctx = Interpolation::Context.fabricate(ctx)
            @size_tracker = size_tracker
            @errors = []
            @blocks = {}
            @value_bytesizes = {}

            interpolate! if valid?
          end

          def valid?
            errors.none?
          end

          def errors
            @errors + @config.errors + @ctx.errors + @blocks.values.flat_map(&:errors)
          end

          def size
            @blocks.size
          end

          def interpolated
            @result if valid?
          end

          private

          attr_reader :size_tracker

          def interpolate!
            @result = @config.replace! do |node|
              break if @errors.any?
              next node unless node_might_contain_interpolation_block?(node)

              matches = BLOCK_REGEXP.scan(node)
              next node if matches.empty?

              blocks = interpolate_blocks(matches)
              break unless @errors.none? && blocks.present?

              get_interpolated_node_content!(node, blocks)
            end
          end

          def node_might_contain_interpolation_block?(node)
            node.is_a?(String) && node.include?(BLOCK_PREFIX)
          end

          def interpolate_blocks(matches)
            matches.map do |match, data|
              block = (@blocks[match] ||= Interpolation::Block.new(match, data, ctx))

              break @errors.push('too many interpolation blocks') if @blocks.size > MAX_BLOCKS
              break unless block.valid?

              block
            end
          end

          def get_interpolated_node_content!(node, blocks)
            if used_inside_a_string?(node, blocks)
              interpolate_string_node!(node, blocks)
            else
              interpolate_whole_node!(blocks.first)
            end
          end

          def interpolate_string_node!(node, blocks)
            return too_large! unless fits?(interpolated_size(node, blocks))

            position = 0

            interpolated_node = blocks.each_with_object(+'') do |block, result|
              start = node.index(block.to_s, position)

              result << node[position...start] << block.value.to_s
              position = start + block.length
            end

            interpolated_node << node[position..]
            size_tracker&.add(interpolated_node.bytesize)
            interpolated_node
          end

          def interpolate_whole_node!(block)
            return block.value unless size_tracker

            bytes = value_bytesize(block)
            return too_large! unless fits?(bytes)

            size_tracker.add(bytes)
            block.value
          end

          def interpolated_size(node, blocks)
            blocks.sum(node.bytesize) { |block| value_bytesize(block) - block.to_s.bytesize }
          end

          def value_bytesize(block)
            @value_bytesizes[block.to_s] ||= block.value.to_s.bytesize
          end

          def fits?(bytes)
            return true unless size_tracker
            return true if size_tracker.fits?(bytes)
            return true unless ::Gitlab::Ci::Config::FeatureFlags.enabled?(:ci_limit_interpolated_config_size)

            size_tracker.reject(bytes)
            false
          end

          def too_large!
            @errors.push(TOO_LARGE_ERROR)

            nil
          end

          def used_inside_a_string?(node, blocks)
            blocks.count > 1 || node.length != blocks.first.length
          end
        end
      end
    end
  end
end
