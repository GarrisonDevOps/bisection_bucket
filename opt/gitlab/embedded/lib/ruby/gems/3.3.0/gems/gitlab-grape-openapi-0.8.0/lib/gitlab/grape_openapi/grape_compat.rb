# frozen_string_literal: true

module Gitlab
  module GrapeOpenapi
    # Isolates the Grape internals this gem reads so version differences live in
    # one place.
    #
    # Grape < 3.2 stores each declared validation as a Hash; Grape >= 3.2 stores
    # a frozen validator instance instead (ruby-grape/grape#2657). Both shapes
    # are normalized to the Hash the converters expect.
    module GrapeCompat
      class << self
        # Declared validations for a single attribute, newest scope only.
        def validations_for(route, attribute)
          validations = declared_validations(route)
          return unless validations

          validations.filter_map do |validation|
            normalized = normalize(validation)
            normalized if normalized && normalized[:attributes].include?(attribute)
          end
        end

        # Every declared validation for a route, normalized, newest scope only.
        # Unlike `validations_for` this keeps group validators (mutually_exclusive
        # and friends) whose `:attributes` span several params.
        def all_validations(route)
          validations = declared_validations(route)
          return [] unless validations

          validations.filter_map { |validation| normalize(validation) }
        end

        # The `desc:` an author writes on `route_param`. Grape forwards only `type:` into
        # the `requires` it declares internally and discards the rest, so the description
        # never reaches the route's params. It survives on the namespace whose space is
        # the `:placeholder` segment. Searched innermost first.
        def route_param_desc(route, name)
          return unless route.app.respond_to?(:inheritable_setting)

          namespaces = route.app.inheritable_setting&.namespace_stackable&.[](:namespace) || []
          namespace = namespaces.reverse.find { |candidate| candidate.space.to_s == ":#{name}" }
          options = namespace&.options
          return unless options.is_a?(Hash)

          desc = options[:desc]
          desc if desc.is_a?(String)
        end

        private

        # The route's raw, un-normalized validation stack, and the only place this
        # gem reaches into Grape for it.
        #
        # Reads `new_values` rather than `[]` or `route[:saved_validations]` on
        # purpose: those also include validations inherited from parent scopes,
        # which would change the generated output.
        def declared_validations(route)
          route.app.inheritable_setting.namespace_stackable.new_values[:validations]
        end

        def normalize(validation)
          if validation.is_a?(Hash) # Grape < 3.2
            # Do not mutate the author's own Hash; add the derived key on a copy.
            return validation.merge(full_names: full_names_for(validation[:params_scope], validation[:attributes]))
          end

          # Grape 3.2's ContractScopeValidator declares no attributes, so it maps
          # to no parameter.
          return unless validation.respond_to?(:attrs)

          {
            attributes: validation.attrs,
            validator_class: validation.class,
            # Grape 3.2 exposes no public reader for the validator options, which
            # carry regexp patterns and limits. Switch to the reader if one is
            # added upstream.
            options: validation.instance_variable_get(:@options),
            opts: { fail_fast: validation.fail_fast? },
            # Full bracketed paths (e.g. "filter[x]") for cross-field constraints
            # in nested scopes; equal to the bare name at the root. No public
            # reader for the scope on 3.2, hence the ivar.
            full_names: full_names_for(validation.instance_variable_get(:@scope), validation.attrs)
          }
        end

        # Maps each attribute to its full bracketed path via the param scope, so a
        # nested `x` becomes "filter[x]" while a top-level `x` stays "x". Falls
        # back to the bare name if the scope cannot resolve it.
        def full_names_for(scope, attributes)
          Array(attributes).map do |attribute|
            if scope.respond_to?(:full_name)
              scope.full_name(attribute).to_s
            else
              attribute.to_s
            end
          end
        end
      end
    end
  end
end
