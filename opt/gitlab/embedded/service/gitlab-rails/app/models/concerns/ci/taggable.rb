# frozen_string_literal: true

module Ci
  module Taggable
    extend ActiveSupport::Concern
    include Gitlab::Utils::StrongMemoize

    included do
      after_save :save_tags

      attribute :tag_list, Gitlab::Database::Type::TagListType.new

      scope :tagged_with, ->(tags, like_search_enabled: false) do
        names = Gitlab::Ci::Tags::Parser.new(tags).parse

        if !like_search_enabled && names.any? && ci_runner_tag_filter_by_tag_ids_enabled?
          with_all_tags_by_name(names)
        else
          names
            .map { |tag| with_tag(tag, like_search_enabled: like_search_enabled) }
            .reduce(:and)
        end
      end

      scope :with_tag, ->(name, like_search_enabled: false) do
        next with_all_tags_by_name([name]) if !like_search_enabled && ci_runner_tag_filter_by_tag_ids_enabled?

        query = taggings_join_model.scoped_taggables

        if like_search_enabled
          query = query.where(tag_id: Tag.where("name LIKE ?", "%#{sanitize_sql_like(name)}%")) # rubocop:disable GitlabSecurity/SqlInjection -- we are sanitizing
        else
          query = query.where(tag_id: Tag.where(name: name))
        end

        where_exists(query)
      end

      # The planner can't estimate a tag's taggings from its name, so we look up the IDs first. One subquery
      # matches every tag, so planning time doesn't grow with the tag count. Tag names are unique, so fewer
      # IDs than distinct names means a tag doesn't exist.
      scope :with_all_tags_by_name, ->(names) do
        names = names.uniq
        tag_ids = Tag.named(names).limit(names.size).pluck(:id)
        next none if tag_ids.size < names.size

        taggings = taggings_join_model.scoped_taggables_in_partition.where(tag_id: tag_ids)
        relation = where_exists(taggings)
        next relation if tag_ids.one?

        relation.where('(?) = ?', taggings.select('COUNT(*)'), tag_ids.size)
      end
    end

    class_methods do
      def ci_runner_tag_filter_by_tag_ids_enabled?
        Feature.enabled?(:ci_runner_tag_filter_by_tag_ids, Feature.current_request)
      end
    end

    def tag_list
      Gitlab::Ci::Tags::TagList.new(context_tags.map(&:name))
    end
    strong_memoize_attr :tag_list

    def tag_list=(new_tags)
      parsed_new_list = Gitlab::Ci::Tags::Parser.new(new_tags).parse
      write_attribute('tag_list', parsed_new_list)
      instance_variable_set(:@tag_list, parsed_new_list)
    end

    def reload(*args)
      clear_memoization(:tag_list)
      super(*args)
    end

    private

    def context_tags
      tags
    end

    def tag_list_cache_set?
      strong_memoized?(:tag_list)
    end

    def save_tags
      return unless tag_list_cache_set?

      tags = find_or_create_tags_from_list(tag_list.uniq)
      current_tags = context_tags
      old_tags = current_tags - tags
      new_tags = tags - current_tags

      taggings.where(tag_id: old_tags).delete_all if old_tags.present?
      Gitlab::Ci::Tags::BulkInsert.bulk_insert_tags!([self]) if new_tags.present?

      taggings.reset
      context_tags.reset

      true
    end

    def find_or_create_tags_from_list(tags)
      Ci::Tag.find_or_create_all_with_like_by_name(tags)
    end
  end
end
