# frozen_string_literal: true

module Gitlab
  class Experiment
    module BaseInterface
      extend ActiveSupport::Concern

      class_methods do
        def configure
          yield Configuration
        end

        def experiment_name(name = nil, suffix: true, suffix_word: 'experiment')
          name = (name.presence || self.name).to_s.underscore.sub(%r{(?<char>[_/]|)#{suffix_word}$}, '')
          name = "#{name}#{Regexp.last_match(:char) || '_'}#{suffix_word}"
          suffix ? name : name.sub(/_#{suffix_word}$/, '')
        end

        def base?
          self == Gitlab::Experiment || name == Configuration.base_class
        end

        def constantize(name = nil)
          return self if name.nil?

          experiment_class = experiment_name(name).classify
          experiment_class.safe_constantize || begin
            return Configuration.base_class.constantize unless Configuration.strict_registration

            raise UnregisteredExperiment, <<~ERR
              No experiment registered for `#{name}`. Please register the experiment by defining a class:

              class #{experiment_class} < #{Configuration.base_class}
                control
                candidate { 'candidate' }
              end
            ERR
          end
        end

        def from_param(id)
          %r{/?(?<name>.*):(?<key>.*)$} =~ id
          name = CGI.unescape(name) if name
          constantize(name).new(name).tap { |e| e.context.key(key) }
        end
      end

      def initialize(name = nil, variant_name = nil, **context)
        raise ArgumentError, 'name is required' if name.blank? && self.class.base?

        @_name = self.class.experiment_name(name, suffix: false)
        @_context = Context.new(self, **context)
        @_assigned_variant_name = cache_variant(variant_name) { nil } if variant_name.present?

        yield self if block_given?
      end

      def inspect
        "#<#{self.class.name || 'AnonymousClass'}:#{format('0x%016X', __id__)} name=#{name} context=#{context.value}>"
      end

      def run(variant_name)
        behaviors.freeze
        context.freeze

        block = behaviors[variant_name]
        raise BehaviorMissingError, "the `#{variant_name}` variant hasn't been registered" if block.nil?

        result = block.call
        publish(result) if enabled?

        result
      end

      def id
        "#{name}:#{context.key}"
      end

      alias_method :to_param, :id

      def process_redirect_url(url)
        return unless Configuration.redirect_url_validator&.call(url)

        track('visited', url:)
        url # return the url, which allows for mutation
      end

      def key_for(source, seed = name)
        return source if source.is_a?(String)

        source = source.keys + source.values if source.is_a?(Hash)

        ingredients = Array(source).map { |v| identify(v) }
        ingredients.unshift(seed).unshift(Configuration.context_key_secret)

        Digest::SHA2.new(Configuration.context_key_bit_length).hexdigest(ingredients.join('|')) # rubocop:disable Fips/OpenSSL
      end

      # @deprecated
      def variant_names
        Configuration.deprecated(
          :variant_names,
          'instead use `behavior.names`, which includes :control',
          version: '0.8.0'
        )

        behaviors.keys - [:control]
      end
    end
  end
end
