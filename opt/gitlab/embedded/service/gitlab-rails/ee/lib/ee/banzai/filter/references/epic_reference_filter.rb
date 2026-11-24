# frozen_string_literal: true

module EE
  module Banzai
    module Filter
      module References
        # HTML filter that replaces epic references with links. References to
        # epics that do not exist are ignored.
        #
        # This filter supports cross-project/group references.
        module EpicReferenceFilter
          extend ActiveSupport::Concern

          def references_in(text, pattern = object_class.reference_pattern)
            replace_references_in_text_with_html(::Gitlab::Utils::Gsub.gsub_with_limit(text, pattern,
              limit: ::Banzai::Filter::FILTER_ITEM_LIMIT)) do |match_data|
              symbol = match_data[object_sym]
              if object_class.reference_valid?(symbol)
                yield match_data[0], symbol.to_i, nil, match_data[:group], match_data
              end
            end
          end

          def url_for_object(epic, group)
            urls = ::Gitlab::Routing.url_helpers
            urls.group_epic_url(group, epic, only_path: context[:only_path])
          end

          def reference_class(object_sym, tooltip: false)
            super
          end

          def data_attributes_for(original, group, object, original_href: nil, link_reference: false)
            {
              original: original,
              link: original_href.present?,
              original_href: original_href,
              link_reference: link_reference,
              group: group.id,
              group_path: group.full_path,
              iid: object.iid,
              object_sym => object.id
            }
          end

          def parent_records(parent, ids)
            return ::Epic.none unless parent.is_a?(Group)

            parent.epics.iid_in(ids.to_a)
          end

          def parent_type
            :group
          end
        end
      end
    end
  end
end
