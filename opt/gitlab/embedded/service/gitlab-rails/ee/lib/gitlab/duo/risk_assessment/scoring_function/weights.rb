# frozen_string_literal: true

module Gitlab
  module Duo
    module RiskAssessment
      module ScoringFunction
        # Declares what each input is worth, and refuses anything it cannot
        # resolve.
        #
        # A key is derived from a domain or a dimension that was looked up first,
        # so a weight cannot name something that does not exist. Plain string
        # keys would survive a rename by matching nothing, and the score would
        # quietly lose those points.
        #
        # Checked while the class body runs, which is safe because both
        # registries are static code. A failure can only mean a programming
        # error, never a missing row or a bad environment, so failing at boot
        # is better than failing quietly on every assessment.
        #
        # The total is not checked here: no declaration knows it is the last
        # one. A spec over every version holds that, where a call at the end of
        # a class body could be left out.
        module Weights
          extend ActiveSupport::Concern

          # A weight naming something that does not exist.
          UnknownWeight = Class.new(StandardError)

          included do
            class_attribute :claim_weights, default: {}.freeze
            class_attribute :signal_weights, default: {}.freeze
            class_attribute :mitigation_weights, default: {}.freeze
          end

          class_methods do
            # Weight the claim about one risk domain. The domain has to be in
            # the catalog, because the flow is only asked about domains that are.
            def weigh_domain(domain_name, max, scale: nil)
              domain = Domain.all.find { |candidate| candidate.name == domain_name.to_s }

              unless domain
                raise UnknownWeight,
                  "#{weight_owner}: no domain named '#{domain_name}'. " \
                    "The catalog has: #{Domain.all.map(&:name).join(', ')}"
              end

              self.claim_weights = claim_weights.merge(domain.name => claim_config(max, scale))
            end

            def weigh_signal(signal, dimension, max)
              self.signal_weights = signal_weights.merge(dimension_key(signal, dimension, mitigation: false) => max)
            end

            def weigh_mitigation(signal, dimension, max)
              self.mitigation_weights =
                mitigation_weights.merge(dimension_key(signal, dimension, mitigation: true) => max)
            end

            def claim_budget
              claim_weights.sum { |_key, config| claim_ceiling(config) }
            end

            def signal_budget
              signal_weights.values.sum
            end

            # A scale that tops out below 1.0 cannot award the whole weight, and
            # counting the unreachable part would compress every score.
            def claim_ceiling(config)
              return config[:max] unless config[:scale]

              config[:max] * config[:scale].values.max
            end

            private

            def claim_config(max, scale)
              scale ? { max: max, scale: scale.freeze } : { max: max }
            end

            # An anonymous subclass has no name, so the message would otherwise
            # open with a bare colon.
            def weight_owner
              name || 'anonymous scoring function'
            end

            # Resolves "<signal>.<dimension>" from parts that must both exist,
            # and refuses a weight pointed at the wrong channel: a mitigation
            # subtracts, so scoring one as a signal would invert its meaning.
            def dimension_key(signal, dimension, mitigation:)
              signal_class = ::Gitlab::Duo::RiskAssessment::SignalsExtractor.signal_class_for(signal)

              raise UnknownWeight, "#{weight_owner}: no signal named '#{signal}' is registered" unless signal_class

              unless signal_class.dimensions.key?(dimension.to_sym)
                raise UnknownWeight,
                  "#{weight_owner}: #{signal} declares no dimension '#{dimension}'. " \
                    "It has: #{signal_class.dimensions.each_key.to_a.join(', ')}"
              end

              if signal_class.mitigation? != mitigation
                raise UnknownWeight,
                  "#{weight_owner}: #{signal} is #{signal_class.mitigation? ? 'a mitigation' : 'a signal'}, " \
                    "but is weighted as #{mitigation ? 'a mitigation' : 'a signal'}"
              end

              "#{signal_class.signal_name}.#{dimension}"
            end
          end
        end
      end
    end
  end
end
