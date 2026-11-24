# frozen_string_literal: true

module Gitlab
  module Duo
    module Developments
      class SweBenchSeeder
        class GroupManager
          GROUP_PATH = 'gitlab-duo'
          SUBGROUP_PATH = 'swe-bench-seeded-data'

          def self.find_or_create_parent_group(user)
            group = Group.find_by_full_path(GROUP_PATH)

            if group
              puts "Found existing parent group: #{GROUP_PATH}"
              return group
            end

            puts "Parent group '#{GROUP_PATH}' not found. Creating a new one..."

            # Creating organizations is not permitted on Self-Managed/Dedicated
            # instances (single-organization model), so fall back to the default
            # organization. See architectural decision 007.
            # rubocop:disable Gitlab/PreventOrganizationFirst -- No other way as this is seeding process
            # We rely on earlier seed from db/fixtures/production/002_default_organization.rb.
            org = ::Organizations::Organization.first
            # rubocop:enable Gitlab/PreventOrganizationFirst

            raise "No seeded organization found. Ensure the default organization has been seeded." unless org

            group_params = {
              name: GROUP_PATH,
              path: GROUP_PATH,
              organization: org,
              visibility_level: org.visibility_level
            }

            response = Groups::CreateService.new(user, group_params).execute

            raise "Failed to create parent group: #{response.errors.full_messages.join(', ')}" if response.error?

            puts "Created parent group: #{GROUP_PATH}"
            response[:group]
          end

          def self.find_or_create_subgroup(parent_group, user)
            subgroup_full_path = "#{GROUP_PATH}/#{SUBGROUP_PATH}"
            subgroup = Group.find_by_full_path(subgroup_full_path)

            if subgroup
              puts "Found existing subgroup: #{subgroup_full_path}"
              return subgroup
            end

            puts "Subgroup '#{subgroup_full_path}' not found. Creating a new one..."

            subgroup_params = {
              name: SUBGROUP_PATH,
              path: SUBGROUP_PATH,
              parent_id: parent_group.id,
              organization: parent_group.organization,
              visibility_level: parent_group.visibility_level
            }

            response = Groups::CreateService.new(user, subgroup_params).execute

            raise "Failed to create subgroup: #{response.errors.full_messages.join(', ')}" if response.error?

            puts "Created subgroup: #{subgroup_full_path}"
            response[:group]
          end
        end
      end
    end
  end
end
