# frozen_string_literal: true

module Banzai
  module Filter
    module References
      # HTML filter that replaces iteration references with links.
      class IterationReferenceFilter < AbstractReferenceFilter
        self.reference_type = :iteration
        self.object_class   = Iteration

        include ::Gitlab::Utils::StrongMemoize

        def parent_records(parent, ids)
          return Iteration.none unless valid_context?(parent)

          iteration_ids = ids.map { |y| y[:iteration_id] }.compact
          unless iteration_ids.empty?
            id_relation = find_iterations(parent, ids: iteration_ids)
          end

          iteration_names = ids.map { |y| y[:iteration_name] }.compact
          unless iteration_names.empty?
            iteration_relation = find_iterations(parent, names: iteration_names)
          end

          relation = [id_relation, iteration_relation].compact
          return ::Iteration.none if relation.all?(::Iteration.none)

          ::Iteration.from_union(relation).includes(:group, :iterations_cadence) # rubocop: disable CodeReuse/ActiveRecord
        end

        def find_object(parent_object, id)
          key = reference_cache.records_per_parent[parent_object].keys.find do |k|
            k[:iteration_id] == id[:iteration_id] || k[:iteration_name] == id[:iteration_name]
          end

          reference_cache.records_per_parent[parent_object][key] if key
        end

        # Transform a symbol extracted from the text to a meaningful value
        #
        # This method has the contract that if a string `ref` refers to a
        # record `record`, then `parse_symbol(ref) == record_identifier(record)`.
        #
        # This contract is slightly broken here, as we only have either the iteration_id
        # or the iteration_name, but not both.  But below, we have both pieces of information.
        # It's accounted for in `find_object`
        def parse_symbol(symbol, match_data)
          if symbol
            # when parsing links, there is no `match_data[:iteration_id]`, but `symbol`
            # holds the id
            { iteration_id: symbol.to_i, iteration_name: nil }
          else
            {
              iteration_id: match_data[:iteration_id]&.to_i,
              iteration_name: match_data[:iteration_name]&.tr('"', '')
            }
          end
        end

        # This method has the contract that if a string `ref` refers to a
        # record `record`, then `class.parse_symbol(ref) == record_identifier(record)`.
        # See note in `parse_symbol` above
        def record_identifier(record)
          { iteration_id: record.id, iteration_name: record.name }
        end

        def valid_context?(parent)
          group_context?(parent) || project_context?(parent)
        end

        def group_context?(parent)
          parent.is_a?(Group)
        end

        def project_context?(parent)
          parent.is_a?(Project)
        end

        def references_in(text, pattern = ::Iteration.reference_pattern)
          # We'll handle here the references that follow the `reference_pattern`.
          # Other patterns (for example, the link pattern) are handled by the
          # default implementation.
          return super(text, pattern) if pattern != ::Iteration.reference_pattern

          replace_references_in_text_with_html(text.gsub(pattern)) do |match_data|
            ident = identifier(match_data)
            yield match_data[0], ident, match_data[:project], match_data[:namespace], match_data
          end
        end

        def find_iterations(parent, ids: nil, names: nil)
          finder_params = iteration_finder_params(parent, ids: ids, names: names)

          IterationsFinder.new(user, finder_params).execute(skip_authorization: true)
        end

        def iteration_finder_params(parent, ids: nil, names: nil)
          parms = ids.present? ? { id: ids } : { title: names }

          { parent: parent, include_ancestors: true }.merge(parms)
        end

        def url_for_object(iteration, _parent)
          ::Gitlab::Routing
            .url_helpers
            .iteration_url(iteration, only_path: context[:only_path])
        end

        def object_link_title(_object, _matches)
          'Iteration'
        end

        def parent
          project || group
        end

        def requires_unescaping?
          true
        end

        def reference_class(object_sym, tooltip: false)
          [super, 'has-popover'].join(' ')
        end

        def data_attributes_for(original, parent, object, **_attrs)
          super.merge({ namespace_path: parent.full_path })
        end
      end
    end
  end
end
