# frozen_string_literal: true

module Tasks
  module Gitlab
    module Nav
      class VariantGenerator
        def initialize(dumper:)
          @dumper = dumper
        end

        def simulate_saas!(state)
          check_environment!

          original_env = ENV['GITLAB_SIMULATE_SAAS']
          ENV['GITLAB_SIMULATE_SAAS'] = state.to_s

          yield

          ENV['GITLAB_SIMULATE_SAAS'] = original_env
        end

        def simulate_ff!(state)
          check_environment!

          all_flags = Feature.register_definitions.values

          original_value = {}
          actor = @dumper.user
          all_flags.each do |flag|
            original_value[flag.name] = Feature.enabled?(flag.name, actor)
            if state
              Feature.enable(flag.name, actor)
            else
              Feature.disable(flag.name, actor)
            end
          end

          yield

          all_flags.each do |flag|
            if original_value[flag.name]
              Feature.enable(flag.name, actor)
            else
              Feature.disable(flag.name, actor)
            end
          end
        end

        # Generates an exhaustive navigation inventory by simulating the navigation in four distinct environments:
        #
        # * Self-managed, all feature flags disabled
        # * SaaS, all feature flags disabled
        # * Self-managed, all feature flags enabled
        # * SaaS, all feature flags enabled
        #
        # The results are unioned together such that the inventory contains all possible entries, with tags indicating
        # which environment(s) a particular item appears in.
        #
        def dump
          variants = []

          simulate_ff!(false) do
            simulate_saas!(false) do
              variants << @dumper.dump(tags: ['sm'])
            end

            simulate_saas!(true) do
              variants << @dumper.dump(tags: ['dotcom'])
            end
          end

          simulate_ff!(true) do
            simulate_saas!(false) do
              variants << @dumper.dump(tags: %w[sm ff])
            end

            simulate_saas!(true) do
              variants << @dumper.dump(tags: %w[dotcom ff])
            end
          end

          combine(*variants)
        end

        def check_environment!
          raise "Not safe for use in production!" if Rails.env.production?
        end

        # Return the set of tags required to make this menu item appear. If it
        # is always present, return no tags.
        #
        def compare_variants(menus)
          # Evaluate each variant based on the tags applied
          #
          tags = menus.filter_map { |g| g[:tags] }
          combined = []

          # Menu item only appeared when a feature flag was enabled
          #
          if (tags.include?(%w[sm ff]) && tags.exclude?(['sm'])) ||
              (tags.include?(%w[dotcom ff]) && tags.exclude?(['dotcom']))
            combined << 'ff'
          end

          # Menu item appeared in either SM or dotcom, but not both
          #
          unique_tags = tags.flatten.uniq
          if unique_tags.include?('dotcom') && unique_tags.exclude?('sm')
            combined << 'dotcom'
          elsif unique_tags.include?('sm') && unique_tags.exclude?('dotcom')
            combined << 'sm'
          end

          combined
        end

        def combine_menus!(*menus)
          return [] if menus.empty?

          # FIXME: Loses ordering information
          groups = menus.group_by { |menu| menu[:id] || menu[:title] }
          groups.map do |_, group|
            sub_items = group.flat_map { |g| g[:items] }.compact
            items = combine_menus!(*sub_items)

            group[0].merge(
              items: items,
              tags: compare_variants(group)
            )
          end
        end

        def combine(*variants)
          variants[0].zip(*variants[1..]).map do |menus|
            combine_menus!(*menus)[0] # combine_menus! merges into the first element
          end
        end
      end
    end
  end
end
