# frozen_string_literal: true

module Gitlab
  module Duo
    module RiskAssessment
      module Signals
        # A deterministic risk signal computed from GitLab data.
        #
        # Signals are deliberately separate from the categorical claims the
        # classification flow returns. Anything measurable is measured here so
        # that the score stays reproducible.
        class Base
          include ::Gitlab::Utils::StrongMemoize

          class Dimension
            attr_reader :name, :method_name

            def initialize(name:, label:, method_name:)
              @name = name
              @label = label
              @method_name = method_name
            end

            def label
              # rubocop:disable Gettext/StaticIdentifier -- must be interpolated by caller because subclasses
              # define translated strings in the body of the class with N_(...), which cannot be namespaced.
              s_(@label)
              # rubocop:enable Gettext/StaticIdentifier
            end
          end

          class_attribute :_label, instance_accessor: false, instance_predicate: false
          class_attribute :dimensions, default: {}.freeze, instance_predicate: false
          class_attribute :mitigation, default: false

          def self.signal_name
            name.demodulize.underscore
          end

          # Whether this signal reports a mitigation rather than a risk.
          #
          # Both channels are 0..1 with 1 meaning "as much as this signal can
          # report", so a mitigation has to be declared rather than inferred
          # from a negative value.
          def self.mitigation!
            self.mitigation = true
          end

          # Human-readable name for this signal stored untranslated (wrap in N_) and translated by the caller at
          # read time.
          def self.set_label(text)
            self._label = text
          end

          def self.label
            s_(_label) if _label
          end

          def self.add_dimension(name, label, method_name = nil)
            # Never mutate dimensions to avoid leaking state between subclasses.
            self.dimensions = dimensions.merge(
              name => Dimension.new(name: name, label: label, method_name: method_name.presence || name)
            )
          end

          def initialize(merge_request)
            @merge_request = merge_request
          end

          # Whether this signal can be answered for this merge request at all.
          #
          # Unavailable is not the same as "answered zero". An unavailable
          # signal lowers confidence and is reported in missing, so a
          # project without coverage reports does not silently look safe.
          def available?
            raise NotImplementedError
          end

          # Normalized values in 0..1, keyed by symbol. 0 means this signal
          # sees no risk; 1 means as risky as this signal can report.
          def extract
            dimensions.transform_values do |dimension|
              # rubocop: disable GitlabSecurity/PublicSend -- known list of dimensions with no risk of leaking to
              # other methods
              public_send(dimension.method_name)
              # rubocop: enable GitlabSecurity/PublicSend
            end
          end

          private

          attr_reader :merge_request

          def project
            merge_request.project
          end

          # Cheaper than diff_stats when only paths are needed: a single pluck
          # on merge_request_diff_files rather than a Gitaly DiffStats call.
          def changed_paths
            merge_request.modified_paths
          end
          strong_memoize_attr :changed_paths

          # Saturating ramp, so a 5000-line change does not outweigh a
          # 500-line one by a factor of ten. Everything at or above
          # saturation_at reads as maximally risky for that dimension.
          def ramp(value, saturation_at)
            return 0.0 if value.to_f <= 0 || saturation_at.to_f <= 0

            [value.to_f / saturation_at, 1.0].min.round(4)
          end
        end
      end
    end
  end
end
